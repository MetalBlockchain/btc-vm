// Command btcvm-devnet creates a BTCVM subnet and chain on a local
// Metal network, paying with the pre-funded ewoq key that local networks
// allocate. It is for development only: the ewoq key is public.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/MetalBlockchain/metalgo/genesis"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/formatting/address"
	"github.com/MetalBlockchain/metalgo/vms/secp256k1fx"
	"github.com/MetalBlockchain/metalgo/wallet/subnet/primary"

	"github.com/MetalBlockchain/btcvm/vm"
)

func main() {
	uri := flag.String("uri", primary.LocalAPIURI, "node API URI")
	genesisPath := flag.String("genesis", "", "BTCVM genesis JSON file")
	subnetFlag := flag.String("subnet", "", "existing subnet ID (default: create one)")
	name := flag.String("name", "btcvm", "chain name")
	ewoqKeyOut := flag.String("ewoq-key-out", "", "write the local network's pre-funded (public) ewoq key as a btcvm-l1 key file, and exit")
	flag.Parse()

	if *ewoqKeyOut != "" {
		if err := writeEWOQKey(*ewoqKeyOut); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *genesisPath == "" {
		log.Fatal("-genesis is required")
	}
	genesisBytes, err := os.ReadFile(*genesisPath)
	if err != nil {
		log.Fatal(err)
	}
	if !json.Valid(genesisBytes) {
		log.Fatalf("%s is not valid JSON", *genesisPath)
	}

	ctx := context.Background()
	kc := secp256k1fx.NewKeychain(genesis.EWOQKey)

	subnetID := ids.Empty
	if *subnetFlag != "" {
		if subnetID, err = ids.FromString(*subnetFlag); err != nil {
			log.Fatalf("invalid -subnet: %v", err)
		}
	} else {
		wallet, err := primary.MakePWallet(ctx, *uri, kc, primary.WalletConfig{})
		if err != nil {
			log.Fatalf("failed to sync P-chain wallet: %v", err)
		}
		tx, err := wallet.IssueCreateSubnetTx(&secp256k1fx.OutputOwners{
			Threshold: 1,
			Addrs:     []ids.ShortID{genesis.EWOQKey.Address()},
		})
		if err != nil {
			log.Fatalf("failed to create subnet: %v", err)
		}
		subnetID = tx.ID()
	}

	wallet, err := primary.MakePWallet(ctx, *uri, kc, primary.WalletConfig{
		SubnetIDs: []ids.ID{subnetID},
	})
	if err != nil {
		log.Fatalf("failed to sync P-chain wallet: %v", err)
	}
	tx, err := wallet.IssueCreateChainTx(subnetID, genesisBytes, vm.ID, nil, *name)
	if err != nil {
		log.Fatalf("failed to create chain: %v", err)
	}

	out, _ := json.Marshal(map[string]string{
		"vmID":     vm.ID.String(),
		"subnetID": subnetID.String(),
		"chainID":  tx.ID().String(),
	})
	fmt.Println(string(out))
}

// writeEWOQKey writes the ewoq key in btcvm-l1's key file format, for
// devnet scripts. The key is public: it only ever holds local-network funds.
func writeEWOQKey(path string) error {
	addr, err := address.Format("P", constants.GetHRP(constants.LocalID), genesis.EWOQKey.Address().Bytes())
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(map[string]string{
		"privateKey":    genesis.EWOQKey.String(),
		"pChainAddress": addr,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
