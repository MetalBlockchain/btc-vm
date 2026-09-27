// Command btcvm-l1 creates a BTCVM L1 on a Metal network: a subnet, the
// BTCVM chain in it, and the conversion to an L1 validated by a node.
//
//	btcvm-l1 key -out p-chain-key.json
//	    create the P-Chain key that pays for and owns the L1; fund its address
//	btcvm-l1 balance -key p-chain-key.json
//	btcvm-l1 create -key p-chain-key.json -genesis genesis.json -node-uri http://127.0.0.1:9660
//	    create the subnet and chain and convert them to an L1 validated by the
//	    node at -node-uri, printing the IDs as JSON
//	btcvm-l1 node-id -cert staker.crt
//	    the NodeID a node's staking certificate gives it (to check a backup)
//	btcvm-l1 request | approve | submit | register | remove | top-up | validators
//	    add and remove the L1's validators (validators.go)
//
// -uri is the P-Chain API to use (default: -node-uri).
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/MetalBlockchain/metalgo/api/info"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/staking"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/formatting/address"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/vms/components/avax"
	"github.com/MetalBlockchain/metalgo/vms/platformvm"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/txs"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/message"
	"github.com/MetalBlockchain/metalgo/vms/secp256k1fx"
	"github.com/MetalBlockchain/metalgo/wallet/subnet/primary"

	"github.com/MetalBlockchain/btcvm/vm"
)

// keyFile is the P-Chain key, stored with 0600 permissions.
type keyFile struct {
	PrivateKey string `json:"privateKey"`
	PAddress   string `json:"pChainAddress"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: btcvm-l1 key|balance|addresses|import|create|node-id|request|approve|submit|register|remove|top-up|disable|validators [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "key":
		err = cmdKey(os.Args[2:])
	case "balance":
		err = cmdBalance(os.Args[2:])
	case "addresses":
		err = cmdAddresses(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "create":
		err = cmdCreate(os.Args[2:])
	case "node-id":
		err = cmdNodeID(os.Args[2:])
	case "request":
		err = cmdRequest(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "submit":
		err = cmdSubmit(os.Args[2:])
	case "register":
		err = cmdRegister(os.Args[2:])
	case "remove":
		err = cmdRemove(os.Args[2:])
	case "top-up":
		err = cmdTopUp(os.Args[2:])
	case "validators":
		err = cmdValidators(os.Args[2:])
	case "disable":
		err = cmdDisable(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatalf("btcvm-l1 %s: %v", os.Args[1], err)
	}
}

func pAddress(key *secp256k1.PrivateKey, networkID uint32) (string, error) {
	return address.Format("P", constants.GetHRP(networkID), key.Address().Bytes())
}

func readKey(path string) (*secp256k1.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, err
	}
	key := new(secp256k1.PrivateKey)
	if err := key.UnmarshalJSON([]byte(`"` + kf.PrivateKey + `"`)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

func networkIDFlag(fs *flag.FlagSet) *uint {
	return fs.Uint("network-id", uint(constants.MainnetID), "Metal network ID (1 = mainnet, 5 = tahoe testnet)")
}

func cmdKey(args []string) error {
	fs := flag.NewFlagSet("key", flag.ExitOnError)
	out := fs.String("out", "", "file to write the key to")
	networkID := networkIDFlag(fs)
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a key", *out)
	}
	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		return err
	}
	addr, err := pAddress(key, uint32(*networkID))
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(keyFile{PrivateKey: key.String(), PAddress: addr}, "", "  ")
	if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Println(addr)
	return nil
}

// cmdNodeID prints the NodeID of a staking certificate.
func cmdNodeID(args []string) error {
	fs := flag.NewFlagSet("node-id", flag.ExitOnError)
	certPath := fs.String("cert", "", "the node's staking certificate (staker.crt)")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*certPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("not a PEM certificate")
	}
	cert, err := staking.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	fmt.Println(ids.NodeIDFromCert(cert))
	return nil
}

// cmdAddresses prints the key's addresses on the P-, X- and C-Chains. METAL
// sent to the X- or C-Chain address can be moved to the P-Chain with import.
func cmdAddresses(args []string) error {
	fs := flag.NewFlagSet("addresses", flag.ExitOnError)
	keyPath := fs.String("key", "", "P-Chain key file")
	networkID := networkIDFlag(fs)
	_ = fs.Parse(args)
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	hrp := constants.GetHRP(uint32(*networkID))
	p, _ := address.Format("P", hrp, key.Address().Bytes())
	x, _ := address.Format("X", hrp, key.Address().Bytes())
	fmt.Printf("P-Chain: %s\nX-Chain: %s\nC-Chain: %s\n", p, x, key.EthAddress().Hex())
	return nil
}

// cmdImport moves the key's METAL from the C-Chain (or, with -from x, the
// X-Chain) to the P-Chain: an export there, then an import on the P-Chain.
// The C-Chain keeps -keep METAL to pay the export fee; the X-Chain export
// pays its fixed fee out of the amount.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	keyPath := fs.String("key", "", "P-Chain key file")
	uri := fs.String("uri", "https://api.metalblockchain.org", "API with the C- and P-Chains")
	keep := fs.Float64("keep", 0.05, "METAL to leave on the C-Chain for the export fee")
	from := fs.String("from", "c", "chain to move METAL from: c or x")
	_ = fs.Parse(args)
	if *from != "c" && *from != "x" {
		return errors.New("-from must be c or x")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	kc := secp256k1fx.NewKeychain(key)
	wallet, err := primary.MakeWallet(ctx, *uri, kc, kc, primary.WalletConfig{})
	if err != nil {
		return err
	}
	cWallet, pWallet := wallet.C(), wallet.P()
	cChainID := cWallet.Builder().Context().BlockchainID
	owner := secp256k1fx.OutputOwners{Threshold: 1, Addrs: []ids.ShortID{key.Address()}}

	if *from == "x" {
		xWallet := wallet.X()
		xCtx := xWallet.Builder().Context()
		balances, err := xWallet.Builder().GetFTBalance()
		if err != nil {
			return err
		}
		have := balances[xCtx.AVAXAssetID]
		if have > xCtx.BaseTxFee {
			amount := have - xCtx.BaseTxFee
			tx, err := xWallet.IssueExportTx(constants.PlatformChainID, []*avax.TransferableOutput{{
				Asset: avax.Asset{ID: xCtx.AVAXAssetID},
				Out:   &secp256k1fx.TransferOutput{Amt: amount, OutputOwners: owner},
			}})
			if err != nil {
				return fmt.Errorf("exporting from the X-Chain: %w", err)
			}
			log.Printf("exported %.4f METAL from the X-Chain in %s", float64(amount)/float64(units.Avax), tx.ID())
		} else {
			log.Printf("nothing to export from the X-Chain (%d nMETAL)", have)
		}
		tx, err := pWallet.IssueImportTx(xCtx.BlockchainID, &owner)
		if err != nil {
			return fmt.Errorf("importing to the P-Chain: %w", err)
		}
		log.Printf("imported to the P-Chain in %s", tx.ID())
		return nil
	}

	// The C-Chain balance is in wei (18 decimals); atomic amounts are in
	// nMETAL (9 decimals).
	wei, err := cWallet.Builder().GetBalance()
	if err != nil {
		return err
	}
	have := new(big.Int).Div(wei, big.NewInt(1_000_000_000)).Uint64()
	margin := uint64(*keep * float64(units.Avax))
	if have > margin {
		amount := have - margin
		tx, err := cWallet.IssueExportTx(constants.PlatformChainID, []*secp256k1fx.TransferOutput{{
			Amt: amount, OutputOwners: owner,
		}})
		if err != nil {
			return fmt.Errorf("exporting from the C-Chain: %w", err)
		}
		log.Printf("exported %.4f METAL from the C-Chain in %s", float64(amount)/float64(units.Avax), tx.ID())
	} else {
		log.Printf("nothing to export from the C-Chain (%d nMETAL)", have)
	}

	tx, err := pWallet.IssueImportTx(cChainID, &owner)
	if err != nil {
		return fmt.Errorf("importing to the P-Chain: %w", err)
	}
	log.Printf("imported to the P-Chain in %s", tx.ID())
	return nil
}

func cmdBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	keyPath := fs.String("key", "", "P-Chain key file")
	uri := fs.String("uri", "http://127.0.0.1:9660", "P-Chain API")
	_ = fs.Parse(args)
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	bal, err := platformvm.NewClient(*uri).GetBalance(context.Background(), []ids.ShortID{key.Address()})
	if err != nil {
		return err
	}
	fmt.Printf("%d nMETAL (%.4f METAL) unlocked\n", bal.Unlocked, float64(bal.Unlocked)/float64(units.Avax))
	return nil
}

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	keyPath := fs.String("key", "", "P-Chain key file; pays the fees and owns the subnet")
	genesisPath := fs.String("genesis", "", "BTCVM genesis JSON")
	nodeURI := fs.String("node-uri", "http://127.0.0.1:9660", "API of the node that will validate the L1")
	uri := fs.String("uri", "", "P-Chain API (default: -node-uri)")
	name := fs.String("name", "btcvm", "chain name")
	balance := fs.Float64("validator-balance", 5, "METAL to prepay the validator's continuous fee (about 1.3 METAL a month)")
	subnetFlag := fs.String("subnet", "", "existing subnet to use instead of creating one")
	chainFlag := fs.String("chain", "", "existing chain to use instead of creating one (needs -subnet)")
	networkID := networkIDFlag(fs)
	_ = fs.Parse(args)
	if *keyPath == "" || (*genesisPath == "" && *chainFlag == "") {
		return errors.New("-key and -genesis are required")
	}
	if *uri == "" {
		*uri = *nodeURI
	}

	ctx := context.Background()
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	owner := &secp256k1fx.OutputOwners{Threshold: 1, Addrs: []ids.ShortID{key.Address()}}
	kc := secp256k1fx.NewKeychain(key)

	nodeID, pop, err := info.NewClient(*nodeURI).GetNodeID(ctx)
	if err != nil {
		return fmt.Errorf("reading the validator node's ID: %w", err)
	}
	log.Printf("validator %s", nodeID)

	subnetID := ids.Empty
	if *subnetFlag != "" {
		if subnetID, err = ids.FromString(*subnetFlag); err != nil {
			return err
		}
	} else {
		wallet, err := primary.MakePWallet(ctx, *uri, kc, primary.WalletConfig{})
		if err != nil {
			return err
		}
		tx, err := wallet.IssueCreateSubnetTx(owner)
		if err != nil {
			return fmt.Errorf("creating subnet: %w", err)
		}
		subnetID = tx.ID()
		log.Printf("created subnet %s", subnetID)
	}

	wallet, err := primary.MakePWallet(ctx, *uri, kc, primary.WalletConfig{SubnetIDs: []ids.ID{subnetID}})
	if err != nil {
		return err
	}

	chainID := ids.Empty
	if *chainFlag != "" {
		if chainID, err = ids.FromString(*chainFlag); err != nil {
			return err
		}
	} else {
		genesis, err := os.ReadFile(*genesisPath)
		if err != nil {
			return err
		}
		if !json.Valid(genesis) {
			return fmt.Errorf("%s is not valid JSON", *genesisPath)
		}
		tx, err := wallet.IssueCreateChainTx(subnetID, genesis, vm.ID, nil, *name)
		if err != nil {
			return fmt.Errorf("creating chain: %w", err)
		}
		chainID = tx.ID()
		log.Printf("created chain %s", chainID)
	}

	// BTCVM has no validator manager contract. The manager chain is the
	// BTCVM chain itself, so the validator set stays as created until one
	// is added; balance top-ups need no manager.
	pOwner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{key.Address()}}
	convertTx, err := wallet.IssueConvertSubnetToL1Tx(subnetID, chainID, nil, []*txs.ConvertSubnetToL1Validator{{
		NodeID:                nodeID.Bytes(),
		Weight:                100,
		Balance:               uint64(*balance * float64(units.Avax)),
		Signer:                *pop,
		RemainingBalanceOwner: pOwner,
		DeactivationOwner:     pOwner,
	}})
	if err != nil {
		return fmt.Errorf("converting to an L1: %w", err)
	}
	log.Printf("converted to an L1 in %s", convertTx.ID())

	out, _ := json.MarshalIndent(map[string]string{
		"networkID":    fmt.Sprint(*networkID),
		"vmID":         vm.ID.String(),
		"subnetID":     subnetID.String(),
		"chainID":      chainID.String(),
		"validationID": subnetID.Append(0).String(),
		"validator":    nodeID.String(),
		"convertTxID":  convertTx.ID().String(),
		"created":      time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	fmt.Println(string(out))
	return nil
}
