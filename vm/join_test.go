package vm

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
)

// TestFreshNodeFollowsChain is a node joining an existing chain: it has
// only genesis, and must recognise the parent of the chain's first block as
// its own genesis, then parse, verify and accept the blocks it is sent.
func TestFreshNodeFollowsChain(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	a := setupVM(t)
	b := setupVM(t)
	require.Equal(a.LastAcceptedID(), b.LastAcceptedID(), "both start at the same genesis")

	acceptBlocks(t, a, 3)
	var chain [][]byte
	for id := a.LastAcceptedID(); ; {
		blk, err := a.GetBlock(ctx, id)
		require.NoError(err)
		if blk.Height() == 0 {
			break
		}
		chain = append([][]byte{blk.Bytes()}, chain...)
		id = blk.Parent()
	}
	require.Len(chain, 3)

	// Bootstrapping fetches from the tip back, parsing each block before
	// its parent is known, and needs each block's parent and height.
	for i := len(chain) - 1; i >= 0; i-- {
		blk, err := b.ParseBlock(ctx, chain[i])
		require.NoError(err, "parsing block %d before its parent", i+1)
		require.Equal(uint64(i+1), blk.Height(), "block %d's height, before its parent is known", i+1)
	}

	first, err := b.ParseBlock(ctx, chain[0])
	require.NoError(err)
	_, err = b.GetBlock(ctx, first.Parent())
	require.NoError(err, "the fresh node knows the first block's parent: its genesis")
	for _, raw := range chain {
		blk, err := b.ParseBlock(ctx, raw)
		require.NoError(err)
		require.NoError(blk.Verify(ctx))
		require.NoError(blk.Accept(ctx))
	}
	require.Equal(a.LastAcceptedID(), b.LastAcceptedID())
}

// TestFreshMainnetNodeFollowsChain is TestFreshNodeFollowsChain with the
// live chain's genesis: mainnet, and the peg reserve in block 1.
func TestFreshMainnetNodeFollowsChain(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	signers := newPegSigners(t, &btcd.BTCVMMainNetParams)
	mining, err := btcutil.NewAddressPubKeyHash(bytes.Repeat([]byte{0x01}, 20), &btcd.BTCVMMainNetParams)
	require.NoError(err)
	config := map[string]any{
		"testNet": false, "mainNet": true,
		"miningAddrs":       []string{mining.EncodeAddress()},
		"pegReserveAddress": signers.address.EncodeAddress(),
		"pegReserveBlocks":  1,
	}
	a := setupVMWithConfig(t, config)
	b := setupVMWithConfig(t, config)
	require.Equal(a.LastAcceptedID(), b.LastAcceptedID(), "both start at the same genesis")

	acceptBlocks(t, a, 3)
	var chain [][]byte
	for id := a.LastAcceptedID(); ; {
		blk, err := a.GetBlock(ctx, id)
		require.NoError(err)
		if blk.Height() == 0 {
			break
		}
		chain = append([][]byte{blk.Bytes()}, chain...)
		id = blk.Parent()
	}
	for i := len(chain) - 1; i >= 0; i-- {
		blk, err := b.ParseBlock(ctx, chain[i])
		require.NoError(err, "parsing block %d before its parent", i+1)
		require.Equal(uint64(i+1), blk.Height())
	}
	for i, raw := range chain {
		blk, err := b.ParseBlock(ctx, raw)
		require.NoError(err)
		require.NoError(blk.Verify(ctx), "verifying block %d", i+1)
		require.NoError(blk.Accept(ctx))
	}
	require.Equal(a.LastAcceptedID(), b.LastAcceptedID())
}

// TestFreshNodeParsesGenesisFromPeer: a peer's reply to a joining node's
// request for blocks runs down to genesis, and the node parses every block
// in it. Genesis has no BIP34 height in its coinbase, so the node must
// recognise it as its own rather than fail to parse it (and then ask for the
// same blocks forever).
func TestFreshNodeParsesGenesisFromPeer(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	for _, config := range []map[string]any{nil, {
		"testNet": false, "mainNet": true,
		"miningAddrs": []string{mainnetMiningAddr(t)},
	}} {
		a := setupVMWithConfig(t, config)
		b := setupVMWithConfig(t, config)
		genesis, err := a.GetBlock(ctx, a.LastAcceptedID())
		require.NoError(err)
		require.Zero(genesis.Height())

		parsed, err := b.ParseBlock(ctx, genesis.Bytes())
		require.NoError(err, "a fresh node parses genesis bytes from a peer")
		require.Equal(genesis.ID(), parsed.ID())
		require.Zero(parsed.Height())
	}
}

func mainnetMiningAddr(t *testing.T) string {
	addr, err := btcutil.NewAddressPubKeyHash(bytes.Repeat([]byte{0x01}, 20), &btcd.BTCVMMainNetParams)
	require.NoError(t, err)
	return addr.EncodeAddress()
}
