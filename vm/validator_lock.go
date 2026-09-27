// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// heldChange is the validator change this node signed last, and the P-Chain
// height of the validator set it was checked against. Until that change is
// on the P-Chain or can no longer be, the node signs no other (see
// validatorManager.Verify).
type heldChange struct {
	Message []byte `json:"message"` // the unsigned Warp message
	Height  uint64 `json:"height"`
	// Changes every admin replaced, while they could still land: never
	// signed again.
	Dropped [][]byte `json:"dropped,omitempty"`
}

// changeLock keeps the held change in a file of its own, written with fsync
// before the node signs: the VM database's writes aren't synced, and a held
// change forgotten in a crash would let a second one through.
//
// A node started on a restored or copied data directory can hold an older
// change than the one it really signed last: it must not sign until an
// operator has checked no change is outstanding (see the CLI's help).
type changeLock struct{ path string }

// read is the held change, or nil if there is none.
func (l changeLock) read() (*heldChange, error) {
	raw, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h heldChange
	if err := json.Unmarshal(raw, &h); err != nil || len(h.Message) == 0 {
		return nil, fmt.Errorf("%s is unreadable; this node signs nothing until an operator checks it", l.path)
	}
	return &h, nil
}

// write replaces the held change durably: a temporary file, synced, renamed
// over the old one, and the directory synced (and, when it's new, the
// directory holding it).
func (l changeLock) write(h heldChange) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	dir := filepath.Dir(l.path)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		// The new directory's own entry must reach the disk too.
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".held-change-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), l.path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
