package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	btcd "github.com/MetalBlockchain/btcvm/btcd"
	"github.com/MetalBlockchain/btcvm/btcd/blockchain"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/mempool"
	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/database/prefixdb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/network/p2p"
	"github.com/MetalBlockchain/metalgo/network/p2p/gossip"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/snow/engine/snowman/block"
	"github.com/MetalBlockchain/metalgo/version"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	_ block.ChainVM = (*VM)(nil)

	errNotInitialized     = errors.New("VM not initialized")
	errAlreadyInitialized = errors.New("VM already initialized")
)

const (
	Name = "btcvm"
)

// ID is the VM ID nodes use to find this plugin: Name, zero-padded to 32
// bytes. The plugin binary must be installed in the node's plugin directory
// under this ID.
var ID = func() ids.ID {
	var id ids.ID
	copy(id[:], Name)
	return id
}()

var Version = &version.Semantic{
	Major: 0,
	Minor: 0,
	Patch: 1,
}

// VM implements the Metal ChainVM interface for Bitcoin
type VM struct {
	// Metal context
	ctx *snow.Context
	db  database.Database

	config *btcd.Config

	// btcd adapter (encapsulates blockchain, mempool, RPC, etc.)
	btcdAdapter *btcd.Server

	// Unified gossip system (replaces separate tx/block gossipers)
	gossipConfig  GossipConfig
	btcSet        *UnifiedBTCSet
	pushGossiper  *gossip.PushGossiper[*BTCGossip]
	pullGossiper  gossip.Gossiper
	p2pNetwork    *p2p.Network
	p2pValidators *p2p.Validators

	// Signs the L1's validator changes an admin approved (validator_manager.go).
	validatorManager *validatorManager

	// Bitcoin components (legacy, kept for compatibility)
	chain *blockchain.BlockChain

	appSender common.AppSender

	// Block management. btcd's chain tip is always lastAccepted; blocks
	// that have been verified but not yet decided live in verifiedBlocks.
	// See block_adapter.go.
	preferred      ids.ID
	lastAccepted   ids.ID
	verifiedBlocks map[ids.ID]*BlockAdapter
	blocksMu       sync.RWMutex

	// Block building
	buildBlockLock sync.Mutex
	blockBuilder   *blockBuilder
	builderLock    sync.Mutex

	// Lifecycle management for gossip goroutines
	cancel       context.CancelFunc
	gossipCtx    context.Context
	shutdownWg   sync.WaitGroup
	bootstrapped bool

	// Lifecycle
	initialized  bool
	stopped      bool
	shutdownChan chan struct{}
}

type genesisBytes struct {
	Config btcd.Config `json:"config"`
}

// parseGenesisBytes parses genesis bytes from JSON
func parseGenesisBytes(data []byte) (*genesisBytes, error) {
	if len(data) == 0 {
		return &genesisBytes{}, nil
	}

	var genesis genesisBytes
	if err := json.Unmarshal(data, &genesis); err != nil {
		return nil, fmt.Errorf("failed to unmarshal genesis bytes: %w", err)
	}

	return &genesis, nil
}

// consensusConfigKeys are genesis settings every node must agree on, which a
// node's chain config may not override.
var consensusConfigKeys = []string{"mainNet", "testNet", "pegReserveAddress", "pegReserveBlocks"}

// applyChainConfig overlays the node's chain config (JSON with the same keys
// as the genesis "config" object) onto the genesis config.
func applyChainConfig(genesisConfig *btcd.Config, configBytes []byte) error {
	if len(configBytes) == 0 {
		return nil
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal(configBytes, &keys); err != nil {
		return err
	}
	for _, key := range consensusConfigKeys {
		if _, ok := keys[key]; ok {
			return fmt.Errorf("%q is a consensus setting and must be set in the genesis", key)
		}
	}

	// Unmarshal onto the genesis config so absent keys keep their values.
	return json.Unmarshal(configBytes, genesisConfig)
}

// Initialize initializes the VM
func (vm *VM) Initialize(
	ctx context.Context,
	snowCtx *snow.Context,
	db database.Database,
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	_ []*common.Fx,
	appSender common.AppSender,
) error {
	// Store context first so we can use the logger
	vm.ctx = snowCtx

	vm.ctx.Log.Debug("entering Initialize")
	defer vm.ctx.Log.Debug("exiting Initialize")

	if vm.initialized {
		return errAlreadyInitialized
	}

	vm.db = db
	vm.appSender = appSender
	vm.shutdownChan = make(chan struct{})
	vm.verifiedBlocks = make(map[ids.ID]*BlockAdapter)

	// Parse genesis to get config
	gb, err := parseGenesisBytes(genesisBytes)
	if err != nil {
		return fmt.Errorf("failed to parse genesis: %w", err)
	}

	// Node-local settings (RPC credentials, indexes, data paths) come from
	// the chain config, which unlike the genesis is private to the node.
	if err := applyChainConfig(&gb.Config, configBytes); err != nil {
		return fmt.Errorf("failed to parse chain config: %w", err)
	}

	config, _, err := btcd.LoadConfig(vm.ctx.NodeID.String(), &gb.Config)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Disable legacy networking
	config.DisableListen = true
	config.DisableDNSSeed = true
	config.MaxPeers = 0
	config.Upnp = false

	vm.config = config

	// Initialize gossip configuration with defaults
	vm.gossipConfig = DefaultGossipConfig()
	if err := vm.gossipConfig.Validate(); err != nil {
		return fmt.Errorf("invalid gossip config: %w", err)
	}

	vm.ctx.Log.Info("initializing Bitcoin VM",
		zap.String("network", config.ChainParams.Name),
		zap.String("dbPath", config.DataDir),
		zap.String("dbType", config.DbType),
		zap.String("gossipConfig", fmt.Sprintf("%+v", vm.gossipConfig)),
	)

	// Initialize btcd adapter (replaces btcd server)
	vm.ctx.Log.Info("Initializing btcd adapter with Metal database")

	btcdAdapter, err := btcd.BtcdMain(vm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize btcd adapter: %w", err)
	}
	vm.btcdAdapter = btcdAdapter

	// Initialize block builder and set callback before starting server
	vm.blockBuilder = newBlockBuilder(vm)
	vm.btcdAdapter.SetOnTxAccepted(vm.blockBuilder.onTxAccepted)
	vm.btcdAdapter.Start()

	// Initialize p2p network. The validator set tracks connected
	// validators for stake-weighted gossip, so it is registered as a
	// connection handler.
	vm.ctx.Log.Info("Initializing p2p network")
	vm.p2pValidators, err = vm.InitializeValidators()
	if err != nil {
		return fmt.Errorf("failed to initialize validators: %w", err)
	}
	reg := prometheus.NewRegistry()
	p2pNet, err := p2p.NewNetwork(vm.ctx.Log, appSender, reg, "p2p", vm.p2pValidators)
	if err != nil {
		return fmt.Errorf("failed to create p2p network: %w", err)
	}
	vm.p2pNetwork = p2pNet
	vm.ctx.Log.Info("p2p network initialized successfully")

	policy, err := parseValidatorAdmins(configBytes)
	if err != nil {
		return fmt.Errorf("failed to parse chain config: %w", err)
	}
	vm.validatorManager, err = newValidatorManager(vm, p2pNet, policy, prefixdb.New([]byte("validator-manager"), vm.db))
	if err != nil {
		return err
	}
	vm.ctx.Log.Info("validator manager ready", zap.Int("validatorAdmins", policy.admins.Len()), zap.Int("validatorAdminThreshold", policy.threshold))

	// Note: Unified gossip system will be initialized in onNormalOperationsStarted()
	// when SetState(snow.NormalOp) is called

	// Use btcd components for compatibility
	vm.chain = vm.btcdAdapter.Chain()
	vm.ctx.Log.Info("btcd adapter initialized successfully")

	// btcd only ever connects accepted blocks (see block_adapter.go), so its
	// tip is the last accepted block.
	bestSnapshot := vm.chain.BestSnapshot()
	if bestSnapshot != nil {
		// Convert btcd hash to Metal ID
		vm.lastAccepted = hashToID(&bestSnapshot.Hash)
		vm.preferred = vm.lastAccepted
		vm.ctx.Log.Info("Set lastAccepted to best block",
			zap.Int32("height", bestSnapshot.Height),
			zap.String("hash", bestSnapshot.Hash.String()),
			zap.String("id", vm.lastAccepted.String()),
		)
	} else {
		vm.ctx.Log.Warn("No best block found, lastAccepted remains empty")
	}

	// Set the callback for relaying transactions via unified gossip
	vm.btcdAdapter.OnTxRelay = func(txns []*mempool.TxDesc) {
		for _, txD := range txns {
			// Use unified gossip if available
			if vm.pushGossiper != nil {
				item := NewTxGossip(txD.Tx)
				vm.pushGossiper.Add(item)
				vm.ctx.Log.Debug("Gossiped transaction via unified gossip",
					zap.String("hash", txD.Tx.Hash().String()))
			}
		}
	}

	// Blocks propagate through Snowman (PushQuery/Put/GetAncestors), never
	// through gossip: a gossiped block would reach btcd without a vote.
	vm.btcdAdapter.OnBlockRelay = func(*btcutil.Block) {}

	vm.initialized = true

	vm.ctx.Log.Info("Bitcoin VM initialized successfully",
		zap.String("lastAccepted", vm.lastAccepted.String()))

	return nil
}

// SetState sets the VM state
func (vm *VM) SetState(ctx context.Context, state snow.State) error {
	vm.ctx.Log.Debug("entering SetState", zap.String("state", state.String()))
	defer vm.ctx.Log.Debug("exiting SetState")

	vm.ctx.Log.Info("setting VM state", zap.String("state", state.String()))

	switch state {
	case snow.StateSyncing:
		vm.bootstrapped = false
		vm.ctx.Log.Info("Bitcoin VM entering state sync")
		return nil

	case snow.Bootstrapping:
		vm.bootstrapped = false
		vm.ctx.Log.Info("Bitcoin VM bootstrapping")
		return nil

	case snow.NormalOp:
		// Only initialize gossip once
		if vm.bootstrapped {
			vm.ctx.Log.Debug("Bitcoin VM already bootstrapped, skipping gossip initialization")
			return nil
		}
		vm.bootstrapped = true
		vm.ctx.Log.Info("Bitcoin VM entering normal operation")

		if err := vm.onNormalOperationsStarted(); err != nil {
			return err
		}

		// Initialize block building after gossip is set up
		return vm.initBlockBuilding()

	default:
		return fmt.Errorf("unknown state: %s", state)
	}
}

// onNormalOperationsStarted initializes gossip and starts gossip goroutines
func (vm *VM) onNormalOperationsStarted() error {
	vm.ctx.Log.Info("Starting normal operations")

	// Create context for gossip goroutines
	vm.gossipCtx, vm.cancel = context.WithCancel(context.Background())

	// Initialize unified gossip system
	if err := vm.initializeGossip(); err != nil {
		return fmt.Errorf("failed to initialize gossip: %w", err)
	}

	// Start gossip loops
	vm.startGossipLoops()

	vm.ctx.Log.Info("Normal operations started successfully")
	return nil
}

// initBlockBuilding starts the block builder goroutines
func (vm *VM) initBlockBuilding() error {
	vm.ctx.Log.Info("initBlockBuilding starting")

	vm.builderLock.Lock()
	defer vm.builderLock.Unlock()

	if vm.blockBuilder == nil {
		return fmt.Errorf("block builder not initialized")
	}

	vm.blockBuilder.start()
	vm.ctx.Log.Info("initBlockBuilding blockBuilder started")

	// Check for existing transactions in mempool
	if mempool := vm.btcdAdapter.TxMemPool(); mempool != nil {
		txCount := len(mempool.MiningDescs())
		vm.ctx.Log.Info("initBlockBuilding checking mempool", zap.Int("txCount", txCount))
		if txCount > 0 {
			vm.blockBuilder.signalCanBuild()
			vm.ctx.Log.Info("initBlockBuilding signaled can build due to existing transactions")
		}
	}

	vm.ctx.Log.Info("initBlockBuilding completed")
	return nil
}

// WaitForEvent waits for block building events
// Implements the block.ChainVM interface for event-driven block production
func (vm *VM) WaitForEvent(ctx context.Context) (common.Message, error) {
	vm.ctx.Log.Info("WaitForEvent called by Snowman engine")

	vm.builderLock.Lock()
	builder := vm.blockBuilder
	vm.builderLock.Unlock()

	if builder == nil {
		vm.ctx.Log.Warn("WaitForEvent called but blockBuilder is nil")
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-vm.shutdownChan:
			return 0, context.Canceled
		}
	}

	msg, err := builder.waitForEvent(ctx)
	vm.ctx.Log.Info("WaitForEvent returning", zap.Uint32("message", uint32(msg)), zap.Error(err))
	return msg, err
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.ctx.Log.Debug("entering Shutdown")
	defer vm.ctx.Log.Debug("exiting Shutdown")

	if vm.stopped {
		return nil
	}

	vm.ctx.Log.Info("shutting down Bitcoin VM")

	// Cancel gossip context to stop goroutines
	if vm.cancel != nil {
		vm.ctx.Log.Info("Cancelling gossip context")
		vm.cancel()
	}

	// Note: p2pNetwork cleanup is handled by the network layer automatically

	// Stop btcd adapter (gracefully closes database and other resources)
	if vm.btcdAdapter != nil {
		vm.ctx.Log.Info("Stopping btcd adapter")
		if err := vm.btcdAdapter.Stop(); err != nil {
			vm.ctx.Log.Error("Error stopping btcd adapter", zap.Error(err))
		}
	}

	// Signal shutdown
	close(vm.shutdownChan)

	// Wait for all gossip goroutines to finish
	vm.ctx.Log.Info("Waiting for gossip goroutines to finish")
	vm.shutdownWg.Wait()

	// Flush btcd's state and release its database now that nothing else can
	// touch the chain.
	if vm.btcdAdapter != nil {
		if err := vm.btcdAdapter.Close(); err != nil {
			vm.ctx.Log.Error("Error closing btcd database", zap.Error(err))
		}
	}

	vm.stopped = true

	vm.ctx.Log.Info("Bitcoin VM shutdown complete")
	return nil
}

// errBlockProcessing is returned by BuildBlock while a verified block is
// waiting to be decided. Blocks can only build on the last accepted block, so
// building now would only create a competing sibling.
var errBlockProcessing = errors.New("a verified block is still being decided")

// BuildBlock builds a new block on top of the last accepted block. The block
// is not written to btcd until it is accepted.
func (vm *VM) BuildBlock(ctx context.Context) (snowman.Block, error) {
	vm.ctx.Log.Info("BuildBlock called by Snowman engine")

	vm.buildBlockLock.Lock()
	defer vm.buildBlockLock.Unlock()

	if vm.btcdAdapter == nil {
		return nil, fmt.Errorf("btcd adapter not initialized")
	}

	if vm.hasProcessingBlocks() {
		return nil, errBlockProcessing
	}

	// Get current block to track parent
	currentBlock, err := vm.getCurrentBlock()
	if err != nil {
		vm.ctx.Log.Error("BuildBlock failed to get current block", zap.Error(err))
		return nil, fmt.Errorf("failed to get current block: %w", err)
	}

	vm.ctx.Log.Info("BuildBlock starting", zap.String("parentHash", currentBlock.Hash().String()))

	// Record build attempt for delay calculation
	if vm.blockBuilder != nil {
		vm.blockBuilder.handleBuildAttempt(*currentBlock.Hash())
	}

	generator := vm.btcdAdapter.GetBlockTemplateGenerator()
	if generator == nil {
		return nil, fmt.Errorf("block template generator not available")
	}

	if len(vm.config.MiningAddrs) == 0 {
		return nil, fmt.Errorf("no mining address configured")
	}

	payToAddr, err := btcutil.DecodeAddress(vm.config.MiningAddrs[0], vm.config.ChainParams)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mining address: %w", err)
	}

	template, err := generator.NewBlockTemplate(payToAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create block template: %w", err)
	}

	template.Block.Header.Nonce = 0
	block := btcutil.NewBlock(template.Block)
	block.SetHeight(template.Height)

	blockAdapter, err := newBlockAdapter(vm, block)
	if err != nil {
		return nil, fmt.Errorf("failed to create block adapter: %w", err)
	}

	if blockAdapter.Parent() != vm.LastAcceptedID() {
		return nil, fmt.Errorf("block template built on %s, not the last accepted block",
			blockAdapter.Parent())
	}

	if vm.blockBuilder != nil {
		vm.blockBuilder.clearPendingSignal()
	}

	vm.ctx.Log.Info("Built block",
		zap.String("id", blockAdapter.ID().String()),
		zap.Uint64("height", blockAdapter.Height()),
		zap.Int("txs", len(block.Transactions())-1))

	return blockAdapter, nil
}

// ParseBlock parses a block from bytes. It does not validate or store it.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (snowman.Block, error) {
	if !vm.initialized {
		return nil, errNotInitialized
	}

	blockAdapter, err := parseBlockAdapter(vm, blockBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	// Return the existing instance for a block that is already verified or
	// accepted, so the engine sees one object per block ID.
	if known, err := vm.getBlock(blockAdapter.ID()); err == nil {
		return known, nil
	}

	vm.ctx.Log.Debug("Parsed block",
		zap.String("blockID", blockAdapter.ID().String()),
		zap.Uint64("height", blockAdapter.Height()),
	)
	return blockAdapter, nil
}

// GetBlock returns a verified or accepted block by ID, or database.ErrNotFound.
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (snowman.Block, error) {
	if !vm.initialized {
		return nil, errNotInitialized
	}
	vm.ctx.Log.Debug("getting block", zap.String("id", blockID.String()))

	return vm.getBlock(blockID)
}

// getBlock returns a verified or accepted block by ID (internal)
func (vm *VM) getBlock(blockID ids.ID) (*BlockAdapter, error) {
	vm.blocksMu.RLock()
	blk, ok := vm.verifiedBlocks[blockID]
	vm.blocksMu.RUnlock()
	if ok {
		return blk, nil
	}

	return acceptedBlockAdapter(vm, blockID)
}

// hasProcessingBlocks reports whether any verified block is waiting to be
// accepted or rejected.
func (vm *VM) hasProcessingBlocks() bool {
	vm.blocksMu.RLock()
	defer vm.blocksMu.RUnlock()
	return len(vm.verifiedBlocks) > 0
}

// LastAcceptedID returns the last accepted block ID.
func (vm *VM) LastAcceptedID() ids.ID {
	vm.blocksMu.RLock()
	defer vm.blocksMu.RUnlock()
	return vm.lastAccepted
}

// onBlockDecided wakes the block builder once no block is left to decide, so
// transactions that were not in the decided block get built into the next
// one. It must not be called with blocksMu held.
func (vm *VM) onBlockDecided() {
	if vm.blockBuilder != nil && vm.blockBuilder.needToBuild() {
		vm.blockBuilder.signalCanBuild()
	}
}

// getCurrentBlock returns the current best block from the blockchain
func (vm *VM) getCurrentBlock() (*btcutil.Block, error) {
	bestHash := vm.chain.BestSnapshot().Hash
	block, err := vm.chain.BlockByHash(&bestHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get current block: %w", err)
	}
	return block, nil
}

// SetPreference sets the preferred block
func (vm *VM) SetPreference(ctx context.Context, blockID ids.ID) error {
	if !vm.initialized {
		return errNotInitialized
	}

	vm.blocksMu.Lock()
	vm.preferred = blockID
	vm.blocksMu.Unlock()
	vm.ctx.Log.Debug("set preference", zap.String("id", blockID.String()))
	return nil
}

// LastAccepted returns the last accepted block ID
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	if !vm.initialized {
		return ids.Empty, errNotInitialized
	}

	return vm.LastAcceptedID(), nil
}

// GetBlockIDAtHeight returns the block ID at a given height
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	if !vm.initialized {
		return ids.Empty, errNotInitialized
	}

	// Get block hash at the specified height
	blockHash, err := vm.chain.BlockHashByHeight(int32(height))
	if err != nil {
		vm.ctx.Log.Error("failed to get block hash at height",
			zap.Uint64("height", height),
			zap.Error(err))
		return ids.Empty, fmt.Errorf("failed to get block hash at height %d: %w", height, err)
	}

	// Convert Bitcoin hash to Metal ID
	blockID := hashToID(blockHash)
	vm.ctx.Log.Debug("retrieved block ID at height",
		zap.Uint64("height", height),
		zap.String("id", blockID.String()))

	return blockID, nil
}

// Version returns the VM version
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// HealthCheck returns health status
func (vm *VM) HealthCheck(ctx context.Context) (interface{}, error) {
	if !vm.initialized {
		return nil, errNotInitialized
	}

	return map[string]interface{}{
		"initialized":  vm.initialized,
		"lastAccepted": vm.LastAcceptedID().String(),
	}, nil
}

// AppGossip handles incoming gossip messages
func (vm *VM) AppGossip(ctx context.Context, nodeID ids.NodeID, msgBytes []byte) error {
	if !vm.initialized {
		return errNotInitialized
	}

	return vm.p2pNetwork.AppGossip(ctx, nodeID, msgBytes)
}

// AppRequest handles incoming app requests
func (vm *VM) AppRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	deadline time.Time,
	msgBytes []byte,
) error {
	return vm.p2pNetwork.AppRequest(ctx, nodeID, requestID, deadline, msgBytes)
}

// AppRequestFailed handles failed app requests
func (vm *VM) AppRequestFailed(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	appErr *common.AppError,
) error {
	return vm.p2pNetwork.AppRequestFailed(ctx, nodeID, requestID, appErr)
}

// AppResponse handles responses to app requests
func (vm *VM) AppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, msgBytes []byte) error {
	return vm.p2pNetwork.AppResponse(ctx, nodeID, requestID, msgBytes)
}

// Connected is called when a new connection is established. The p2p network
// tracks peers for gossip, so it must hear about every connection.
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *version.Application) error {
	return vm.p2pNetwork.Connected(ctx, nodeID, nodeVersion)
}

// Disconnected is called when a connection is terminated
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return vm.p2pNetwork.Disconnected(ctx, nodeID)
}

// NewHTTPHandler returns nil: the VM serves no gRPC-routed HTTP handler.
func (vm *VM) NewHTTPHandler(context.Context) (http.Handler, error) {
	return nil, nil
}

// CreateHandlers creates and returns HTTP handlers
func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	if vm.btcdAdapter == nil {
		return nil, fmt.Errorf("btcd adapter not initialized")
	}

	// Get RPC server from btcd adapter
	rpcServer := vm.btcdAdapter.RPCServer()
	if rpcServer == nil {
		return nil, fmt.Errorf("RPC server not initialized")
	}

	// Start RPC server and get the HTTP handler
	rpcHandler, wsHandler := rpcServer.Start()
	if rpcHandler == nil || wsHandler == nil {
		return nil, fmt.Errorf("failed to get RPC handler")
	}

	vm.ctx.Log.Info("RPC handlers created successfully using btcd adapter",
		zap.Strings("endpoints", []string{"Bitcoin RPC methods via btcd adapter"}),
	)

	return map[string]http.Handler{
		"/rpc":        rpcHandler,
		"/ws":         wsHandler,
		"/validators": vm.validatorManager,
	}, nil
}
