package vm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// crashDirEnv tells the test binary, run as a child, to accept blocks in the
// directory it names and then die without shutting down.
const crashDirEnv = "BTCVM_CRASH_TEST_DIR"

// TestAcceptedBlocksSurviveAKill: the plugin was once killed on a restart
// without shutting down, and btcd lost the blocks still in its caches,
// blocks Snowman had already accepted. A child process accepts blocks and
// is killed; the chain reopened from its directory must have them all.
func TestAcceptedBlocksSurviveAKill(t *testing.T) {
	if dir := os.Getenv(crashDirEnv); dir != "" {
		// The child: accept three blocks, report, and be killed.
		vm := newTestVM(t, dir, nil)
		acceptBlocks(t, vm, 3)
		blk, err := vm.GetBlock(context.Background(), vm.LastAcceptedID())
		require.NoError(t, err)
		fmt.Printf("accepted %d\n", blk.Height())
		os.Stdout.Sync()
		select {} // wait to be killed
	}
	require := require.New(t)
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	child := exec.Command(os.Args[0], "-test.run=^TestAcceptedBlocksSurviveAKill$")
	child.Env = append(os.Environ(), crashDirEnv+"="+dir)
	out, err := child.StdoutPipe()
	require.NoError(err)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	require.NoError(child.Start())
	height := -1
	for scan := bufio.NewScanner(out); scan.Scan(); {
		if h, ok := strings.CutPrefix(scan.Text(), "accepted "); ok {
			height, err = strconv.Atoi(h)
			require.NoError(err)
			break
		}
	}
	require.Equal(3, height, "the child accepts blocks; its stderr: %s", stderr.String())
	require.NoError(child.Process.Kill()) // no Shutdown: the database is never closed
	_, _ = child.Process.Wait()

	vm := newTestVM(t, dir, nil)
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	blk, err := vm.GetBlock(context.Background(), vm.LastAcceptedID())
	require.NoError(err)
	require.Equal(uint64(3), blk.Height(), "every accepted block survives the kill")
}
