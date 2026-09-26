// Command btcvm-blocks reads, from a COPY of a Metal node's database, the
// BTCVM blocks that metalgo's proposervm stored at the given heights, and
// prints each block's transactions as hex, to resubmit ones the chain lost.
// Stop the node and copy its db directory first; never point this at a live
// database.
//
//	btcvm-blocks DB-COPY/mainnet/v1.4.5 CHAIN-ID FROM-HEIGHT TO-HEIGHT
//
// docs/RUNBOOK.md, "Blocks lost after a restart", explains when and how.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/MetalBlockchain/metalgo/database/leveldb"
	"github.com/MetalBlockchain/metalgo/database/prefixdb"
	"github.com/MetalBlockchain/metalgo/database/versiondb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/logging"
	"github.com/MetalBlockchain/metalgo/vms/proposervm/state"

	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: btcvm-blocks DB-COPY CHAIN-ID FROM-HEIGHT TO-HEIGHT")
		os.Exit(2)
	}
	path, chain := os.Args[1], os.Args[2]
	from, _ := strconv.Atoi(os.Args[3])
	to, _ := strconv.Atoi(os.Args[4])
	db, err := leveldb.New(path, nil, logging.NoLog{}, prometheus.NewRegistry())
	if err != nil {
		panic(err)
	}
	defer db.Close()
	chainID, err := ids.FromString(chain)
	if err != nil {
		panic(err)
	}
	vmDB := prefixdb.New([]byte("vm"), prefixdb.New(chainID[:], db))
	st := state.New(versiondb.New(prefixdb.New([]byte("proposervm"), vmDB)))
	last, err := st.GetLastAccepted()
	fmt.Fprintln(os.Stderr, "proposervm last accepted:", last, err)
	for h := from; h <= to; h++ {
		id, err := st.GetBlockIDAtHeight(uint64(h))
		if err != nil {
			fmt.Printf("height %d: %v\n", h, err)
			continue
		}
		blk, err := st.GetBlock(id)
		if err != nil {
			fmt.Printf("height %d %s: %v\n", h, id, err)
			continue
		}
		inner := blk.Block()
		var mb wire.MsgBlock
		if err := mb.BtcDecode(bytes.NewReader(inner), 0, wire.WitnessEncoding); err != nil {
			fmt.Printf("height %d: inner block: %v\n", h, err)
			continue
		}
		fmt.Printf("height %d outer %s inner %s time %s txs %d\n", h, id, mb.BlockHash(), mb.Header.Timestamp.UTC().Format("15:04:05"), len(mb.Transactions))
		for i, tx := range mb.Transactions {
			var buf bytes.Buffer
			_ = tx.Serialize(&buf)
			fmt.Printf("  tx %d %s coinbase=%v %s\n", i, tx.TxHash(), i == 0, hex.EncodeToString(buf.Bytes()))
		}
	}
}
