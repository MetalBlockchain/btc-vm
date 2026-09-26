// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
)

// metalgo starts a plugin with no environment at all (no HOME), in
// metalgo's own working directory, which can be metalgo's data dir, holding
// its database in ./db. btcd's legacy start-up migrations resolved their
// "old home" to "." without HOME and deleted ./db: metalgo's database.
// Starting the VM must leave its working directory exactly as it was.
func TestVMLeavesWorkingDirectoryAlone(t *testing.T) {
	require := require.New(t)
	work := t.TempDir()
	files := map[string]string{
		"db/000001.sst":  "metalgo's database",
		"db/CURRENT":     "MANIFEST-000001",
		"data/keep":      "someone's data dir",
		"btcd.conf":      "someone's config",
		"btcd/db/marker": "a legacy btcd home",
	}
	for name, content := range files {
		path := filepath.Join(work, name)
		require.NoError(os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(os.WriteFile(path, []byte(content), 0o600))
	}
	t.Chdir(work)
	t.Setenv("HOME", "")

	vm := newTestVM(t, t.TempDir(), nil)
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })

	for name, content := range files {
		got, err := os.ReadFile(filepath.Join(work, name))
		require.NoError(err, "%s was removed or moved", name)
		require.Equal(content, string(got), "%s was changed", name)
	}
}

// With a dataDir in the chain config, the VM creates nothing outside it:
// no btcd home directory under the service user's home, which may not be
// writable (ProtectHome, or a home of /nonexistent).
func TestVMCreatesNothingOutsideItsDataDir(t *testing.T) {
	require := require.New(t)
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	vm := newTestVM(t, dir, nil)
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })

	// The NodeID is random per test, so its old-style home can't predate it.
	home := btcutil.AppDataDir("btcdvm/"+vm.ctx.NodeID.String(), false)
	_, err := os.Stat(home)
	require.True(os.IsNotExist(err), "the VM created %s outside its dataDir", home)
	require.DirExists(filepath.Join(dir, "data", "btcdvm-home"))
}
