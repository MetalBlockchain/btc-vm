package main

// The emergency pause. A paused bridge proposes and pays nothing, refunds
// are refused, and a paused signer signs nothing. Deposits made while paused
// stay on Bitcoin and are credited after the bridge resumes.
//
// The pause is a file, paused.json, next to the signer set. That makes it
// something every operator can do alone, for their own process, even when
// nothing else is working: the coordinator pauses the bridge, and each signer
// operator can pause their own signer. Any operator can also pause every
// signer, with a pause signed by their signer key (remotepause.go); only
// each signer's own operator resumes it.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var errPaused = errors.New("the bridge is paused")

type pauseState struct {
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
}

func pausePath(signersPath string) string {
	return filepath.Join(filepath.Dir(signersPath), "paused.json")
}

// paused returns the pause in force for b's signer set, or nil.
func (b *bridge) paused() *pauseState {
	if b.signers == nil || b.signers.path == "" {
		return nil
	}
	raw, err := os.ReadFile(pausePath(b.signers.path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	p := &pauseState{Reason: "unreadable pause file; treated as paused"}
	if err == nil {
		_ = json.Unmarshal(raw, p)
	}
	return p
}

func (p *pauseState) err() error {
	return fmt.Errorf("%w since %s: %s", errPaused, p.Since.UTC().Format(time.RFC3339), p.Reason)
}

// pauseFlags resolves the signer set a pause applies to: -signers for the
// bridge, or -dir for a signer set up with signer-setup.
func pauseFlags(fs *flag.FlagSet) func() (string, error) {
	signersPath := fs.String("signers", "", "the signer set file the bridge (or signer) runs with")
	dir := fs.String("dir", "", "a signer's directory, from signer-setup (instead of -signers)")
	return func() (string, error) {
		switch {
		case *signersPath != "":
			return *signersPath, nil
		case *dir != "":
			return filepath.Join(*dir, setFileName), nil
		}
		return "", errors.New("-signers or -dir is required")
	}
}

func cmdPause(args []string) error {
	fs := flag.NewFlagSet("pause", flag.ExitOnError)
	target := pauseFlags(fs)
	reason := fs.String("reason", "", "why, shown on the website and in alerts")
	remote, keyFile := pauseFlagsRemote(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := target()
	if err != nil {
		return err
	}
	if *reason == "" {
		return errors.New("-reason is required: it is shown to users and in alerts")
	}
	if *remote != "" {
		if *keyFile == "" {
			return errors.New("-remote needs -key-file: your signer key signs the pause")
		}
		set, err := readSignerSet(path)
		if err != nil {
			return err
		}
		return cmdPauseRemote(set, *keyFile, *remote, *reason)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no signer set at %s: %w", path, err)
	}
	if err := writePause(path, pauseState{Reason: *reason, Since: time.Now().UTC()}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Paused. Nothing will be signed or paid until: btcvm resume %s\n", targetArgs(fs))
	printJSON(map[string]any{"paused": true, "file": pausePath(path), "reason": *reason})
	return nil
}

func cmdResume(args []string) error {
	fs := flag.NewFlagSet("resume", flag.ExitOnError)
	target := pauseFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := target()
	if err != nil {
		return err
	}
	// A signed pause made before now is never applied again.
	raw, _ := json.Marshal(pauseState{Reason: "resumed", Since: time.Now().UTC()})
	if err := os.WriteFile(resumedPath(path), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Remove(pausePath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	printJSON(map[string]any{"paused": false})
	return nil
}

// writePause pauses the bridge or signer running with the set at
// signersPath.
func writePause(signersPath string, p pauseState) error {
	raw, _ := json.MarshalIndent(p, "", "  ")
	tmp := pausePath(signersPath) + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, pausePath(signersPath)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(signersPath))
}

// resumedPath records when the operator last resumed.
func resumedPath(signersPath string) string {
	return filepath.Join(filepath.Dir(signersPath), "resumed.json")
}

// targetArgs repeats the -signers or -dir flag given, for the resume hint.
func targetArgs(fs *flag.FlagSet) string {
	out := ""
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "signers" || f.Name == "dir" {
			out = fmt.Sprintf("-%s %s", f.Name, f.Value)
		}
	})
	return out
}
