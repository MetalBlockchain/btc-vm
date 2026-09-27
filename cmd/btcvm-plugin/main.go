// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/MetalBlockchain/metalgo/vms/rpcchainvm"
	"github.com/spf13/cobra"

	"github.com/MetalBlockchain/btcvm/vm"

	log "github.com/inconshreveable/log15"
)

var (
	cfg *config
)

// btcvmMain is the real main function for btcvm. It is necessary to work around
// the fact that deferred functions do not run when os.Exit() is called.
func btcvmMain() error {
	// Load configuration and parse command line
	tcfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg

	// Initialize logging
	if err := initLogging(cfg.LogLevel, cfg.LogDir); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}
	defer log.Info("Shutdown complete")

	// Show version at startup
	log.Info("Starting Bitcoin VM", "version", version())

	// Show configuration
	cfg.show()

	// Get interrupt channel for graceful shutdown
	interrupt := interruptListener()

	// Start profiling if requested
	stopProfiler, err := startProfiler(cfg.CPUProfile, cfg.MemProfile, cfg.HTTPProfile)
	if err != nil {
		log.Error("Failed to start profiler", "error", err)
		return err
	}
	defer stopProfiler()

	// Initialize security features (unveil/pledge on OpenBSD)
	if err := initSecurity(cfg.DataDir, cfg.LogDir); err != nil {
		log.Error("Failed to initialize security features", "error", err)
		return err
	}

	// Return now if an interrupt signal was triggered
	if interruptRequested(interrupt) {
		return nil
	}

	// Create context for VM
	ctx := context.Background()

	// Setup VM serving in a goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Info("Starting btcvm RPC chain VM server")
		errChan <- rpcchainvm.Serve(ctx, &vm.VM{})
	}()

	// metalgo owns this process: it calls the VM's Shutdown, which flushes
	// and closes the chain database, and then the server returns. A signal
	// (systemd sends SIGTERM to every process in the unit) must not end the
	// process first: exiting here skipped Shutdown, and btcd lost the
	// blocks still in its caches, which Snowman had already accepted.
	select {
	case <-interrupt:
		log.Info("Received a stop signal; waiting for metalgo to shut the VM down")
	case err := <-errChan:
		if err != nil {
			log.Error("RPC chain VM server error", "error", err)
			return err
		}
		return nil
	}
	if err := <-errChan; err != nil {
		log.Error("RPC chain VM server error", "error", err)
		return err
	}
	return nil
}

func main() {
	// btcvm-plugin -check-config FILE|-: whether the VM would accept a chain
	// config's validator settings; for installers, before they restart.
	if len(os.Args) == 3 && (os.Args[1] == "-check-config" || os.Args[1] == "--check-config") {
		os.Exit(checkChainConfig(os.Args[2]))
	}

	// Override GC percent if not explicitly set
	if os.Getenv("GOGC") == "" {
		// Set GC to run more frequently to avoid memory spikes
		// This value is optimized for blockchain processing
		debug.SetGCPercent(10)
	}

	// Use cobra for CLI but with enhanced initialization
	rootCmd := &cobra.Command{
		Use:   "btcvm",
		Short: "Bitcoin VM for Metal",
		Long:  "A Bitcoin Virtual Machine implementation running on Metal consensus",
		RunE:  runFunc,
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runFunc(*cobra.Command, []string) error {
	// Work around defer not working after os.Exit()
	if err := btcvmMain(); err != nil {
		return err
	}
	return nil
}
