// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// metalgo starts the plugin with an empty environment (no HOME) in its own
// working directory. The plugin must write nothing there and not depend on
// it being writable: it once made ./.btcvm/logs, and a read-only working
// directory stopped it before it served.
func TestPluginWritesNothingBeforeInitialize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions")
	}
	bin := filepath.Join(t.TempDir(), "btcvm-plugin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cwd := t.TempDir()
	if err := os.Chmod(cwd, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cwd, 0o755) //nolint:errcheck // cleanup
	cmd := exec.Command(bin)
	cmd.Dir = cwd
	cmd.Env = []string{} // as metalgo starts it, minus the runtime address
	out, _ := cmd.CombinedOutput()
	// Without metalgo's runtime address it can only stop there.
	if !strings.Contains(string(out), "VM_RUNTIME_ENGINE_ADDR") {
		t.Fatalf("stopped for another reason than the missing runtime address:\n%s", out)
	}
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("created %s in its working directory", e.Name())
	}
}
