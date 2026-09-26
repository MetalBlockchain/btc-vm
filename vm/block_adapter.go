package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MetalBlockchain/btcvm/btcd/blockchain"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"go.uber.org/zap"
)

// Block lifecycle
//
// btcd's chain state holds accepted blocks and nothing else, so its tip is
// always the last accepted block. Parsing and verifying a block never write to
// btcd: Verify checks the block against the tip with
// CheckConnectBlockTemplate, which is read-only, and Accept is the only place
// a block is connected. Reject therefore has nothing to undo.
//
// The cost is that a block can only be verified on top of the last accepted
// block, so the chain never extends a block that is still being decided.

var (
	errParentNotAccepted = errors.New("parent is not the last accepted block")
	errWrongHeight       = errors.New("block height is not parent height + 1")
	errNonCanonicalBlock = errors.New("block bytes are not canonically encoded")
	errNoCoinbase        = errors.New("block has no coinbase transaction")
)

// BlockAdapter wraps a Bitcoin block and implements the snowman.Block interface
type BlockAdapter struct {
	vm        *VM
	btcBlock  *btcutil.Block
	id        ids.ID
	parentID  ids.ID
	height    uint64
	timestamp time.Time
	bytes     []byte
}

// newBlockAdapter wraps btcBlock, which must already have its height set.
func newBlockAdapter(vm *VM, btcBlock *btcutil.Block) (*BlockAdapter, error) {
	if btcBlock.Height() == btcutil.BlockHeightUnknown {
		return nil, fmt.Errorf("block %s has no height", btcBlock.Hash())
	}

	bytes, err := btcBlock.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize block: %w", err)
	}

	header := &btcBlock.MsgBlock().Header
	return &BlockAdapter{
		vm:        vm,
		btcBlock:  btcBlock,
		id:        hashToID(btcBlock.Hash()),
		parentID:  hashToID(&header.PrevBlock),
		height:    uint64(btcBlock.Height()),
		timestamp: header.Timestamp,
		bytes:     bytes,
	}, nil
}

// acceptedBlockAdapter returns the accepted block with the given ID, or
// database.ErrNotFound.
func acceptedBlockAdapter(vm *VM, blockID ids.ID) (*BlockAdapter, error) {
	block, err := vm.chain.BlockByHash(idToHash(blockID))
	if err != nil {
		return nil, fmt.Errorf("%w: block %s: %v", database.ErrNotFound, blockID, err)
	}
	return newBlockAdapter(vm, block)
}

// parseBlockAdapter decodes a block without validating it against the chain
// or storing it. Its height is read from the BIP34 height in the coinbase,
// which Verify checks against the parent.
func parseBlockAdapter(vm *VM, blockBytes []byte) (*BlockAdapter, error) {
	var msgBlock wire.MsgBlock
	reader := bytes.NewReader(blockBytes)
	if err := msgBlock.BtcDecode(reader, 0, wire.WitnessEncoding); err != nil {
		return nil, fmt.Errorf("failed to deserialize block: %w", err)
	}

	block := btcutil.NewBlock(&msgBlock)

	// Reject bytes that decode to the same block ID but are not the block's
	// canonical encoding, so each ID has exactly one byte representation.
	canonical, err := block.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize block: %w", err)
	}
	if !bytes.Equal(canonical, blockBytes) {
		return nil, errNonCanonicalBlock
	}

	// A block this node already has, genesis included, is its own copy.
	// Genesis has no BIP34 height in its coinbase, and a peer's reply to a
	// joining node's request for blocks runs down to it: failing to parse it
	// would make the node discard the reply and ask again forever.
	if known, err := vm.getBlock(hashToID(block.Hash())); err == nil {
		return known, nil
	}

	if len(msgBlock.Transactions) == 0 {
		return nil, errNoCoinbase
	}
	height, err := blockchain.ExtractCoinbaseHeight(block.Transactions()[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read block height: %w", err)
	}
	block.SetHeight(height)

	return newBlockAdapter(vm, block)
}

// ID returns the block ID
func (b *BlockAdapter) ID() ids.ID {
	return b.id
}

// Parent returns the parent block ID
func (b *BlockAdapter) Parent() ids.ID {
	return b.parentID
}

// Height returns the block height
func (b *BlockAdapter) Height() uint64 {
	return b.height
}

// Timestamp returns the block timestamp
func (b *BlockAdapter) Timestamp() time.Time {
	return b.timestamp
}

// Bytes returns the serialized block bytes
func (b *BlockAdapter) Bytes() []byte {
	return b.bytes
}

// Verify checks that the block is valid on top of the last accepted block. It
// does not modify btcd's chain state.
func (b *BlockAdapter) Verify(ctx context.Context) error {
	b.vm.blocksMu.Lock()
	defer b.vm.blocksMu.Unlock()

	if b.parentID != b.vm.lastAccepted {
		return fmt.Errorf("%w: parent %s, last accepted %s",
			errParentNotAccepted, b.parentID, b.vm.lastAccepted)
	}

	tipHeight := b.vm.chain.BestSnapshot().Height
	if b.height != uint64(tipHeight)+1 {
		return fmt.Errorf("%w: height %d, parent height %d",
			errWrongHeight, b.height, tipHeight)
	}

	// Full consensus validation (sanity, BIP34 height, timestamps,
	// difficulty bits, UTXO spends, scripts, coinbase value) against the
	// tip, without connecting the block.
	if err := b.vm.chain.CheckConnectBlockTemplate(b.btcBlock); err != nil {
		return fmt.Errorf("block %s failed validation: %w", b.id, err)
	}

	b.vm.verifiedBlocks[b.id] = b

	b.vm.ctx.Log.Debug("Block verified",
		zap.String("id", b.id.String()),
		zap.Uint64("height", b.height))
	return nil
}

// Accept connects the block to btcd's chain, making it the new tip.
func (b *BlockAdapter) Accept(ctx context.Context) error {
	if err := b.accept(); err != nil {
		return err
	}
	b.vm.onBlockDecided()

	b.vm.ctx.Log.Info("Block accepted",
		zap.String("id", b.id.String()),
		zap.Uint64("height", b.height))
	return nil
}

func (b *BlockAdapter) accept() error {
	b.vm.blocksMu.Lock()
	defer b.vm.blocksMu.Unlock()

	if b.parentID != b.vm.lastAccepted {
		return fmt.Errorf("%w: accepting %s with parent %s, last accepted %s",
			errParentNotAccepted, b.id, b.parentID, b.vm.lastAccepted)
	}

	isMainChain, isOrphan, err := b.vm.btcdAdapter.ProcessBlockNoPoW(b.btcBlock)
	if err != nil {
		return fmt.Errorf("failed to connect accepted block %s: %w", b.id, err)
	}
	if isOrphan || !isMainChain {
		return fmt.Errorf("accepted block %s did not become the chain tip (orphan=%t, mainChain=%t)",
			b.id, isOrphan, isMainChain)
	}

	delete(b.vm.verifiedBlocks, b.id)
	b.vm.lastAccepted = b.id
	return nil
}

// Reject drops the block. It was never written to btcd, and its transactions
// never left the mempool, so there is nothing to undo.
func (b *BlockAdapter) Reject(ctx context.Context) error {
	b.vm.blocksMu.Lock()
	delete(b.vm.verifiedBlocks, b.id)
	b.vm.blocksMu.Unlock()

	b.vm.onBlockDecided()

	b.vm.ctx.Log.Info("Block rejected",
		zap.String("id", b.id.String()),
		zap.Uint64("height", b.height))
	return nil
}
