package btcd

import "testing"

// The public read-only RPC user (rpcLimitUser) is exposed on the websites'
// /rpc. It must not be able to broadcast, rescan, load filters or run
// whole-chain scans, and searchrawtransactions must stay bounded.
func TestLimitedUserIsReadOnly(t *testing.T) {
	for _, m := range []string{"sendrawtransaction", "rescan", "rescanblocks", "loadtxfilter",
		"getnetworkhashps", "notifyreceived", "notifyspent", "notifynewtransactions"} {
		if _, ok := rpcLimited[m]; ok {
			t.Errorf("%s is available to the limited user", m)
		}
	}
	for _, m := range []string{"getblockcount", "getblock", "getblockhash", "getrawtransaction", "searchrawtransactions", "gettxout"} {
		if _, ok := rpcLimited[m]; !ok {
			t.Errorf("%s should stay available to the limited user", m)
		}
	}
	if maxSearchRawTransactionsCount > 1000 {
		t.Errorf("searchrawtransactions cap %d is too large", maxSearchRawTransactionsCount)
	}
}
