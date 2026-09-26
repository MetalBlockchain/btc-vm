package main

// btcvm signer-setup: the ceremony that sets up separate signers. Only
// public information changes hands:
//
//  1. Each operator, on their own machine:  signer-setup init
//     makes (or imports) their key and a signer card: name, URL, public key
//     and a signature proving they hold the key.
//  2. The coordinator:                        signer-setup coordinator
//     makes the coordinator key, which signs every request to the signers.
//  3. The coordinator, with every card:       signer-setup assemble
//     builds the signer set (keys, networks, coordinator key, policy) and
//     prints its fingerprint.
//  4. Each operator:                          signer-setup join
//     checks the set, confirms its fingerprint with the others over a
//     separate channel, and writes the service files.
//  5. Anyone, any time:                       signer-setup check
//
// Every step runs interactively in a terminal, or from flags alone (-yes)
// for scripts and agents. Private keys are only ever read from a hidden
// prompt, a file or stdin: never from a flag, which would land in shell
// history and the process list.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2/ecdsa"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
)

// operatorCard introduces one signer. It holds nothing secret.
type operatorCard struct {
	Name      string `json:"name"`
	URL       string `json:"url"` // where the coordinator reaches the signer
	PublicKey string `json:"publicKey"`
	// TLSPin is the signer's transport key pin, for an https URL
	// (transport.go); absent on cards made before transport keys.
	TLSPin string `json:"tlsPin,omitempty"`
	Proof  string `json:"proof"` // signature over the rest, by the key
}

func (c operatorCard) digest() []byte {
	msg := "btcvm signer card v1\n" + c.Name + "\n" + c.URL + "\n" + c.PublicKey
	if c.TLSPin != "" {
		msg = "btcvm signer card v2\n" + c.Name + "\n" + c.URL + "\n" + c.PublicKey + "\n" + c.TLSPin
	}
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}

func makeCard(name, signerURL, tlsPin string, key *btcec.PrivateKey) operatorCard {
	c := operatorCard{Name: name, URL: signerURL, TLSPin: tlsPin, PublicKey: hex.EncodeToString(key.PubKey().SerializeCompressed())}
	c.Proof = hex.EncodeToString(ecdsa.Sign(key, c.digest()).Serialize())
	return c
}

// verify checks the card's proof: whoever made it holds the key.
func (c operatorCard) verify() error {
	raw, err := hex.DecodeString(c.PublicKey)
	if err != nil {
		return fmt.Errorf("card %q: %w", c.Name, err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return fmt.Errorf("card %q: %w", c.Name, err)
	}
	sigRaw, err := hex.DecodeString(c.Proof)
	if err != nil {
		return fmt.Errorf("card %q: %w", c.Name, err)
	}
	sig, err := ecdsa.ParseDERSignature(sigRaw)
	if err != nil || !sig.Verify(c.digest(), pub) {
		return fmt.Errorf("card %q: the proof does not match its key", c.Name)
	}
	return nil
}

// --- prompting ---------------------------------------------------------------

// prompter asks questions in a terminal. With interactive false, every
// answer must come from a flag, and asking fails.
type prompter struct {
	in          *bufio.Reader
	out         io.Writer
	interactive bool
	// hidden reads a line without echoing it; nil reads a plain line.
	hidden func() ([]byte, error)
}

// newPrompter is a variable so tests can answer the questions.
var newPrompter = terminalPrompter

func terminalPrompter(yes bool) *prompter {
	p := &prompter{in: bufio.NewReader(os.Stdin), out: os.Stderr}
	fd := int(os.Stdin.Fd())
	if !yes && term.IsTerminal(fd) {
		p.interactive = true
		p.hidden = func() ([]byte, error) { return term.ReadPassword(fd) }
	}
	return p
}

func (p *prompter) line() (string, error) {
	s, err := p.in.ReadString('\n')
	if err != nil && (err != io.EOF || s == "") {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// value returns current if set, else asks, offering def.
func (p *prompter) value(current *string, flagName, question, def string) error {
	if *current != "" {
		return nil
	}
	if !p.interactive {
		if def != "" {
			*current = def
			return nil
		}
		return fmt.Errorf("-%s is required", flagName)
	}
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", question)
	}
	answer, err := p.line()
	if err != nil {
		return err
	}
	if answer == "" {
		answer = def
	}
	if answer == "" {
		return fmt.Errorf("%s is required", strings.ToLower(question))
	}
	*current = answer
	return nil
}

// confirm asks a yes/no question; without a terminal, yes decides.
func (p *prompter) confirm(question string, yes bool) (bool, error) {
	if !p.interactive {
		return yes, nil
	}
	fmt.Fprintf(p.out, "%s [y/N]: ", question)
	answer, err := p.line()
	if err != nil {
		return false, err
	}
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}

// secret reads a line without echo.
func (p *prompter) secret(question string) (string, error) {
	fmt.Fprintf(p.out, "%s: ", question)
	if p.hidden == nil {
		return p.line()
	}
	raw, err := p.hidden()
	fmt.Fprintln(p.out)
	return strings.TrimSpace(string(raw)), err
}

// parsePrivateKey reads a key as 64 hex characters or a compressed-key WIF
// for any network.
func parsePrivateKey(s string) (*btcec.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if raw, err := hex.DecodeString(s); err == nil {
		if len(raw) != 32 {
			return nil, errors.New("a hex private key is 64 characters")
		}
		key, _ := btcec.PrivKeyFromBytes(raw)
		return key, nil
	}
	wif, err := btcutil.DecodeWIF(s)
	if err != nil {
		return nil, errors.New("not a hex private key or a WIF")
	}
	if !wif.CompressPubKey {
		return nil, errors.New("this WIF is for an uncompressed key, which the peg does not use")
	}
	return wif.PrivKey, nil
}

// writeNew writes a file that must not already exist.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readCard(path string) (operatorCard, error) {
	var c operatorCard
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// --- steps -------------------------------------------------------------------

const setupUsage = `btcvm signer-setup: set up separate peg signers (see docs/SIGNERS.md)

  signer-setup init         each operator: make or import a key, and a signer card
  signer-setup coordinator  the coordinator: make the key that signs requests
  signer-setup assemble     the coordinator: build the signer set from every card
  signer-setup join         each operator: check the set and write service files
  signer-setup check        check a signer's setup

Each step asks questions in a terminal. With -yes it takes everything from
flags instead, for scripts and agents. Run "btcvm signer-setup STEP -h".
`

func cmdSignerSetup(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, setupUsage)
		return errors.New("which step?")
	}
	steps := map[string]func([]string) error{
		"init":        setupInit,
		"coordinator": setupCoordinator,
		"assemble":    setupAssemble,
		"join":        setupJoin,
		"check":       setupCheck,
	}
	step, ok := steps[args[0]]
	if !ok {
		fmt.Fprint(os.Stderr, setupUsage)
		return fmt.Errorf("unknown step %q", args[0])
	}
	return step(args[1:])
}

// Files in a signer's directory.
const (
	keyFileName   = "signer.key"
	cardFileName  = "card.json"
	setFileName   = "signers.json"
	envFileName   = "signer.env"
	unitFileName  = "btcvm-signer.service"
	coordKeyName  = "coordinator.key"
	signingLogKey = "signing-log.json"
)

func setupInit(args []string) error {
	fs := flag.NewFlagSet("signer-setup init", flag.ExitOnError)
	dir := fs.String("dir", "", "directory for this signer's files (default /var/lib/btcvm-signer)")
	name := fs.String("name", "", "your name or organisation, shown to the other signers")
	signerURL := fs.String("url", "", "URL the coordinator will reach this signer at, e.g. https://signer.example.com:9700")
	importFile := fs.String("import-key-file", "", "import an existing private key (hex or WIF) from this file, instead of making one")
	importStdin := fs.Bool("import-key-stdin", false, "import an existing private key (hex or WIF) from stdin, instead of making one")
	yes := fs.Bool("yes", false, "no questions: take everything from flags (for scripts and agents)")
	plaintext := fs.Bool("plaintext-key", false, "write the key unencrypted (by default it is encrypted with a passphrase, from the terminal or $"+passphraseEnv+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := newPrompter(*yes)
	if err := p.value(dir, "dir", "Directory for this signer's files", "/var/lib/btcvm-signer"); err != nil {
		return err
	}
	if err := p.value(name, "name", "Your name or organisation, shown to the other signers", ""); err != nil {
		return err
	}
	if err := p.value(signerURL, "url", "URL the coordinator will reach this signer at", ""); err != nil {
		return err
	}
	u, err := url.Parse(*signerURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%q is not an http(s) URL", *signerURL)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return fmt.Errorf("%q: a signer beyond the coordinator's machine is reached over https (with its transport key pinned), never plain http", *signerURL)
	}
	keyPath := filepath.Join(*dir, keyFileName)
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s already exists; this machine already has a signer key", keyPath)
	}

	var key *btcec.PrivateKey
	switch {
	case *importFile != "":
		raw, err := os.ReadFile(*importFile)
		if err != nil {
			return err
		}
		if key, err = parsePrivateKey(string(raw)); err != nil {
			return err
		}
	case *importStdin:
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return err
		}
		if key, err = parsePrivateKey(string(raw)); err != nil {
			return err
		}
	case p.interactive:
		fmt.Fprintln(p.out, "\nA signer key can be made here, which is safest: it never exists anywhere else.")
		fmt.Fprintln(p.out, "Or import one you already hold, for example when moving an existing signer.")
		choice := ""
		if err := p.value(&choice, "", "Make a new key or import one? (new/import)", "new"); err != nil {
			return err
		}
		if strings.HasPrefix(strings.ToLower(choice), "i") {
			pasted, err := p.secret("Paste the private key, as hex or WIF (it is not shown)")
			if err != nil {
				return err
			}
			if key, err = parsePrivateKey(pasted); err != nil {
				return err
			}
			fmt.Fprintf(p.out, "That key's public key is %s\n", hex.EncodeToString(key.PubKey().SerializeCompressed()))
			if ok, err := p.confirm("Is that the public key you expected?", false); err != nil || !ok {
				return errors.New("stopped: the key was not what you expected; nothing was written")
			}
		}
	}
	if key == nil {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		key, _ = btcec.PrivKeyFromBytes(secret[:])
	}

	passphrase := ""
	if !*plaintext {
		if passphrase, err = newPassphrase(p); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := writeKey(keyPath, key, passphrase); err != nil {
		return err
	}
	// The signing log is born with the key: from now on a missing log means
	// a lost one, and the signer refuses to run without it.
	if _, err := createSigningLog(filepath.Join(*dir, signingLogKey)); err != nil {
		return err
	}
	// So is the transport key, for a signer reached over https.
	tlsPin := ""
	if u.Scheme == "https" {
		if tlsPin, err = makeTransportKey(*dir, "btcvm signer "+*name); err != nil {
			return err
		}
	}
	card := makeCard(*name, *signerURL, tlsPin, key)
	raw, _ := json.MarshalIndent(card, "", "  ")
	cardPath := filepath.Join(*dir, cardFileName)
	if err := writeNew(cardPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(p.out, "\nKey written to %s. It never leaves this machine. Back it up offline.\n", keyPath)
	fmt.Fprintf(p.out, "Send %s to the coordinator. It holds no secrets.\n", cardPath)
	printJSON(map[string]string{"keyFile": keyPath, "card": cardPath, "publicKey": card.PublicKey})
	return nil
}

func setupCoordinator(args []string) error {
	fs := flag.NewFlagSet("signer-setup coordinator", flag.ExitOnError)
	dir := fs.String("dir", "", "directory for the coordinator key (default /var/lib/btcvm)")
	yes := fs.Bool("yes", false, "no questions: take everything from flags")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := newPrompter(*yes)
	if err := p.value(dir, "dir", "Directory for the coordinator key", "/var/lib/btcvm"); err != nil {
		return err
	}
	path := filepath.Join(*dir, coordKeyName)
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	key, _ := btcec.PrivKeyFromBytes(secret[:])
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := writeNew(path, []byte(hex.EncodeToString(secret[:])+"\n"), 0o600); err != nil {
		return err
	}
	pub := hex.EncodeToString(key.PubKey().SerializeCompressed())
	// Its transport key, for signers reached over TLS.
	pin, err := makeTransportKey(*dir, "btcvm coordinator")
	if err != nil {
		return err
	}
	fmt.Fprintf(p.out, "Coordinator key written to %s. Pass its public key and TLS pin to signer-setup assemble.\n", path)
	printJSON(map[string]string{"keyFile": path, "coordinatorKey": pub, "coordinatorTLS": pin})
	return nil
}

func setupAssemble(args []string) error {
	var s settings
	fs := flag.NewFlagSet("signer-setup assemble", flag.ExitOnError)
	req := fs.Int("required", 0, "signatures required to move funds")
	coordKey := fs.String("coordinator-key", "", "the coordinator's public key (from signer-setup coordinator)")
	coordTLS := fs.String("coordinator-tls", "", "the coordinator's transport key pin (from signer-setup coordinator), needed if any signer is reached over https")
	out := fs.String("out", "signers.json", "file to write the signer set to")
	cosignersOut := fs.String("cosigners-out", "cosigners.json", "file to write the coordinator's list of signers to")
	previous := fs.String("previous", "", "for a key rotation: the signer set this one replaces (docs/ROTATION.md)")
	yes := fs.Bool("yes", false, "no questions: take everything from flags")
	s.register(fs)
	b := bridgeFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: btcvm signer-setup assemble [flags] CARD.json...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := s.resolve(); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("pass every signer's card.json")
	}
	tiers, err := parseConfirmationTiers(b.tiersFlag, b.depositConfirmations)
	if err != nil {
		return fmt.Errorf("-confirmation-tiers: %w", err)
	}
	b.confirmationTiers = tiers
	if err := b.checkFeeRates(); err != nil {
		return err
	}
	p := newPrompter(*yes)

	set := &signerSet{
		Networks:       &setNetworks{Bitcoin: s.btcNet, BTCVM: s.vmNetwork},
		CoordinatorKey: *coordKey,
		CoordinatorTLS: *coordTLS,
		Policy: &pegPolicy{
			Confirmations: b.depositConfirmations, VMFee: b.vmFee,
			MinFeeRate: b.minFeeRate, MaxFeeRate: b.maxFeeRate,
			MinDeposit: b.minDeposit, MinPegOut: b.minPegOut,
			MaxDeposit: b.maxDeposit, MaxCirculating: b.maxCirculating,
			ConfirmationTiers: b.confirmationTiers,
		},
	}
	seen := map[string]bool{}
	var cosigners []*remoteSigner
	for _, path := range fs.Args() {
		card, err := readCard(path)
		if err != nil {
			return err
		}
		if err := card.verify(); err != nil {
			return err
		}
		if seen[card.PublicKey] {
			return fmt.Errorf("%s: the same key appears twice", path)
		}
		seen[card.PublicKey] = true
		set.Operators = append(set.Operators, card)
		set.PublicKeys = append(set.PublicKeys, card.PublicKey)
		cosigners = append(cosigners, &remoteSigner{URL: card.URL, PublicKey: card.PublicKey, TLSPin: card.TLSPin})
		if card.TLSPin != "" && set.CoordinatorTLS == "" {
			return fmt.Errorf("%s: this signer is reached over TLS, so the set needs -coordinator-tls (from signer-setup coordinator)", path)
		}
	}
	if *req == 0 && p.interactive {
		def := fmt.Sprint(len(set.PublicKeys)/2 + 1)
		answer := ""
		if err := p.value(&answer, "required", fmt.Sprintf("Signatures required, of %d", len(set.PublicKeys)), def); err != nil {
			return err
		}
		fmt.Sscanf(answer, "%d", req)
	}
	set.Required = *req
	if set.Required < 2 && len(set.PublicKeys) > 1 {
		return errors.New("-required must be at least 2 for separate signers to mean anything")
	}
	if set.CoordinatorKey == "" {
		if err := p.value(&set.CoordinatorKey, "coordinator-key", "The coordinator's public key", ""); err != nil {
			return err
		}
	}
	if err := set.load(); err != nil {
		return err
	}
	if seen[set.CoordinatorKey] {
		return errors.New("the coordinator key must not be a signer key")
	}
	// A rotation: the new set names the one it replaces, and that set's
	// before it, so the bridge still sees every coin they hold. Its
	// signers keep running, retired, to move those coins here.
	var replaces *signerSet
	if *previous != "" {
		if replaces, err = readSignerSet(*previous); err != nil {
			return fmt.Errorf("-previous: %w", err)
		}
		set.Previous = append([]priorSet{{Required: replaces.Required, PublicKeys: replaces.PublicKeys}}, replaces.Previous...)
		for _, prior := range set.Previous {
			for _, k := range prior.PublicKeys {
				if seen[k] {
					return errors.New("a key of the new set is in a set it replaces: rotation needs new keys, made on each new signer's machine")
				}
			}
		}
		for _, op := range replaces.Operators {
			cosigners = append(cosigners, &remoteSigner{URL: op.URL, PublicKey: op.PublicKey, TLSPin: op.TLSPin})
		}
		if err := set.load(); err != nil {
			return err
		}
	}

	vmAddr, _ := set.address(s.vmParams)
	btcAddr, _ := set.address(s.btcParams)
	summary := map[string]any{
		"fingerprint":       set.fingerprint(),
		"required":          fmt.Sprintf("%d of %d", set.Required, len(set.PublicKeys)),
		"bitcoinPegAddress": btcAddr.EncodeAddress(),
		"btcvmReserve":      vmAddr.EncodeAddress(),
		"signerSet":         *out,
		"cosigners":         *cosignersOut,
	}
	if replaces != nil {
		oldBTC, _ := replaces.address(s.btcParams)
		summary["replaces"] = replaces.fingerprint()
		summary["replacesPegAddress"] = oldBTC.EncodeAddress()
		fmt.Fprintf(p.out, "This set replaces %s (peg address %s). Its signers keep running, retired, and move every coin it holds to this set.\n",
			replaces.fingerprint(), oldBTC.EncodeAddress())
	}
	if ok, err := p.confirm(fmt.Sprintf("Write a %d-of-%d signer set with fingerprint %s?", set.Required, len(set.PublicKeys), set.fingerprint()), true); err != nil || !ok {
		return errors.New("stopped; nothing was written")
	}
	if err := writeSetFile(*out, set); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(cosigners, "", "  ")
	if err := writeNew(*cosignersOut, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(p.out, "Send %s to every signer, and read out the fingerprint %s to each of them over a separate channel.\n", *out, set.fingerprint())
	printJSON(summary)
	return nil
}

// operatorName is the name on signer me's card, or "retired signer" for a
// key of a set this one replaced.
func operatorName(set *signerSet, me int) string {
	if me < 0 {
		return "retired signer"
	}
	return set.Operators[me].Name
}

func mustJSON(v any) []byte {
	raw, _ := json.MarshalIndent(v, "", "  ")
	return append(raw, '\n')
}

func writeSetFile(path string, set *signerSet) error {
	raw, err := json.MarshalIndent(set.publicCopy(), "", "  ")
	if err != nil {
		return err
	}
	return writeNew(path, append(raw, '\n'), 0o644)
}

func setupJoin(args []string) error {
	var s settings
	fs := flag.NewFlagSet("signer-setup join", flag.ExitOnError)
	dir := fs.String("dir", "", "this signer's directory, from signer-setup init (default /var/lib/btcvm-signer)")
	setPath := fs.String("signers", "", "the signer set from the coordinator")
	fingerprint := fs.String("fingerprint", "", "the fingerprint the other signers confirmed (required with -yes)")
	listen := fs.String("listen", "0.0.0.0:9700", "address the signer serves on")
	maxDaily := fs.String("max-daily", "", "most BTC this signer approves moving in 24 hours (0: no limit)")
	bin := fs.String("bin", "/usr/local/bin/btcvm", "path of the btcvm binary, for the service file")
	user := fs.String("user", "btcvm-signer", "system user the service runs as")
	yes := fs.Bool("yes", false, "no questions: take everything from flags")
	s.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := newPrompter(*yes)
	if err := p.value(dir, "dir", "This signer's directory", "/var/lib/btcvm-signer"); err != nil {
		return err
	}
	if err := p.value(setPath, "signers", "Path of the signer set the coordinator sent", ""); err != nil {
		return err
	}
	set, err := readSignerSet(*setPath)
	if err != nil {
		return err
	}
	if len(set.PrivateKeys) > 0 {
		return errors.New("this signer set holds private keys; ask the coordinator for the public one")
	}
	if set.Networks == nil || set.Policy == nil || set.coordKey == nil || len(set.Operators) != len(set.PublicKeys) {
		return errors.New("this signer set was not made by signer-setup assemble")
	}
	s.btcNet, s.vmNetwork = set.Networks.Bitcoin, set.Networks.BTCVM
	if err := s.resolve(); err != nil {
		return err
	}
	for i, card := range set.Operators {
		if err := card.verify(); err != nil {
			return err
		}
		if card.PublicKey != set.PublicKeys[i] {
			return fmt.Errorf("operator %q does not match public key %d", card.Name, i)
		}
	}
	key, err := readKeyFile(filepath.Join(*dir, keyFileName))
	if err != nil {
		return err
	}
	me := set.indexOf(key.PubKey())
	retired := me < 0 && set.retired(key.PubKey()) != nil
	if me < 0 && !retired {
		return errors.New("this signer's key is not in the set")
	}

	vmAddr, _ := set.address(s.vmParams)
	btcAddr, _ := set.address(s.btcParams)
	pol := set.Policy
	fmt.Fprintf(p.out, "\nSigner set: %d of %d, Bitcoin %s, BTCVM %s\n", set.Required, len(set.PublicKeys), s.btcNet, s.vmNetwork)
	for i, c := range set.Operators {
		marker := "  "
		if i == me {
			marker = "* "
		}
		fmt.Fprintf(p.out, "  %s%-24s %s  %s…\n", marker, c.Name, c.URL, c.PublicKey[:16])
	}
	fmt.Fprintf(p.out, "Coordinator key:  %s…\n", set.CoordinatorKey[:16])
	fmt.Fprintf(p.out, "Peg address:      %s (Bitcoin)\n", btcAddr.EncodeAddress())
	fmt.Fprintf(p.out, "Reserve:          %s (BTCVM)\n", vmAddr.EncodeAddress())
	fmt.Fprintf(p.out, "Policy:           %d confirmations; fees %s BTC + %d-%d sat/vB; deposits %s–%s BTC; at most %s BTC circulating\n",
		pol.Confirmations, formatBTC(pol.VMFee), pol.MinFeeRate, pol.MaxFeeRate, formatBTC(pol.MinDeposit),
		capText(pol.MaxDeposit), capText(pol.MaxCirculating))
	fmt.Fprintf(p.out, "Fingerprint:      %s\n\n", set.fingerprint())
	if retired {
		fmt.Fprintln(p.out, "This signer's key belongs to a set this one replaces. Joining makes it a retired")
		fmt.Fprintln(p.out, "signer: it signs nothing but moves of its old set's coins to this set's addresses,")
		fmt.Fprintln(p.out, "and it must keep running until those coins have moved (docs/ROTATION.md).")
		fmt.Fprintln(p.out)
	} else if len(set.Previous) > 0 {
		fmt.Fprintf(p.out, "This set replaces %d earlier set(s); their retired signers move their coins here.\n\n", len(set.Previous))
	}

	switch {
	case *fingerprint != "":
		if *fingerprint != set.fingerprint() {
			return fmt.Errorf("the set's fingerprint is %s, not %s: do not join", set.fingerprint(), *fingerprint)
		}
	case p.interactive:
		fmt.Fprintln(p.out, "Confirm this fingerprint with the coordinator and the other signers over a")
		fmt.Fprintln(p.out, "separate channel (a call, not the channel the file came over).")
		if ok, err := p.confirm("Does everyone see the same fingerprint?", false); err != nil || !ok {
			return errors.New("stopped: fingerprint not confirmed; nothing was written")
		}
	default:
		return errors.New("-fingerprint is required with -yes: pass the fingerprint the other signers confirmed")
	}

	if *maxDaily == "" && p.interactive {
		if err := p.value(maxDaily, "max-daily", "Most BTC this signer approves moving in 24 hours (0: no limit)", "0"); err != nil {
			return err
		}
	}
	if *maxDaily == "" {
		*maxDaily = "0"
	}
	daily, err := parseBTC(*maxDaily)
	if err != nil {
		return fmt.Errorf("-max-daily: %w", err)
	}

	raw, _ := json.MarshalIndent(set.publicCopy(), "", "  ")
	installed := filepath.Join(*dir, setFileName)
	// A rotation replaces the set this signer ran with: keep a copy.
	if old, err := readSignerSet(installed); err == nil && old.fingerprint() != set.fingerprint() {
		kept := filepath.Join(*dir, "signers."+old.fingerprint()+".json")
		if err := writeNew(kept, mustJSON(old.publicCopy()), 0o644); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if err := os.WriteFile(installed, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	envPath := filepath.Join(*dir, envFileName)
	if _, err := os.Stat(envPath); errors.Is(err, os.ErrNotExist) {
		env := fmt.Sprintf(`# Connection settings for this signer's own nodes. Holds passwords: mode 0600,
# never commit it.
BTCVM_NETWORK=%s
BTCVM_RPC=http://127.0.0.1:9650/ext/bc/CHAIN_ID/rpc
BTCVM_RPC_USER=
BTCVM_RPC_PASS=
BITCOIN_NETWORK=%s
BITCOIN_RPC=http://127.0.0.1:%d
BITCOIN_RPC_USER=
BITCOIN_RPC_PASS=
`, s.vmNetwork, s.btcNet, bitcoinRPCPort(s.btcNet))
		if err := writeNew(envPath, []byte(env), 0o600); err != nil {
			return err
		}
	}
	// An encrypted key's passphrase reaches the service as a systemd
	// credential, sealed to this machine (its TPM, where it has one).
	credential, credPath := "", filepath.Join(*dir, "passphrase.cred")
	if raw, err := os.ReadFile(filepath.Join(*dir, keyFileName)); err == nil && isEncryptedKey(raw) {
		credential = fmt.Sprintf("LoadCredentialEncrypted=%s:%s\n", passphraseCredential, credPath)
	}
	unit := fmt.Sprintf(`[Unit]
Description=BTCVM peg signer (%s)
After=network-online.target
Wants=network-online.target

[Service]
User=%s
EnvironmentFile=%s
%sExecStart=%s signer -signers %s -key-file %s -listen %s -log %s -deposits %s -max-daily %d
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, operatorName(set, me), *user, envPath, credential, *bin, installed, filepath.Join(*dir, keyFileName), *listen,
		filepath.Join(*dir, signingLogKey), filepath.Join(*dir, "deposits.json"), daily, *dir)
	unitPath := filepath.Join(*dir, unitFileName)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(p.out, `Joined. Next:
  1. Fill in %s with this signer's own Bitcoin Core and BTCVM nodes.
`, envPath)
	if credential != "" {
		fmt.Fprintf(p.out, `     Seal the key's passphrase for the service (type it, then Ctrl-D):
       sudo systemd-creds encrypt --name=%s --with-key=auto - %s
`, passphraseCredential, credPath)
	}
	fmt.Fprintf(p.out, `  2. Install the service:  sudo cp %s /etc/systemd/system/ && sudo systemctl enable --now btcvm-signer
  3. Check everything:     btcvm signer-setup check -dir %s
  4. Tell the coordinator you are up.
`, unitPath, *dir)
	printJSON(map[string]string{"fingerprint": set.fingerprint(), "signerSet": installed, "env": envPath, "service": unitPath})
	return nil
}

func capText(v int64) string {
	if v == 0 {
		return "no limit"
	}
	return formatBTC(v)
}

// checkResult is one line of signer-setup check.
type checkResult struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func setupCheck(args []string) error {
	var s settings
	fs := flag.NewFlagSet("signer-setup check", flag.ExitOnError)
	dir := fs.String("dir", "/var/lib/btcvm-signer", "this signer's directory")
	signerURL := fs.String("url", "", "also check the signer answers at this URL (default: from its card)")
	s.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var results []checkResult
	add := func(name string, err error, ok string) {
		if err != nil {
			results = append(results, checkResult{name, false, err.Error()})
		} else {
			results = append(results, checkResult{name, true, ok})
		}
	}

	key, keyErr := readKeyFile(filepath.Join(*dir, keyFileName))
	add("key file", keyErr, "present, readable only by its owner")
	set, setErr := readSignerSet(filepath.Join(*dir, setFileName))
	if setErr == nil && len(set.PrivateKeys) > 0 {
		setErr = errors.New("the installed signer set holds private keys")
	}
	if setErr == nil {
		add("signer set", nil, fmt.Sprintf("%d of %d, fingerprint %s", set.Required, len(set.PublicKeys), set.fingerprint()))
	} else {
		add("signer set", setErr, "")
	}
	if keyErr == nil && setErr == nil {
		switch {
		case set.indexOf(key.PubKey()) >= 0:
			add("membership", nil, "this signer's key is in the set")
		case set.retired(key.PubKey()) != nil:
			add("membership", nil, "retired: this signer's key is in a set this one replaced; it only moves that set's coins here")
		default:
			add("membership", errors.New("this signer's key is not in the set"), "")
		}
	}
	if setErr == nil && set.Networks != nil {
		s.btcNet, s.vmNetwork = set.Networks.Bitcoin, set.Networks.BTCVM
	}
	if info, err := os.Stat(filepath.Join(*dir, envFileName)); err == nil && info.Mode().Perm()&0o077 != 0 {
		add("env file", fmt.Errorf("%s is readable by other users; chmod 600 it", envFileName), "")
	}
	if err := s.resolve(); err == nil {
		var height int64
		add("BTCVM node", s.vmChain().rpc.call(&height, "getblockcount"), fmt.Sprintf("answering at %s", s.vmRPC))
		var chainInfo struct {
			Blocks  int64 `json:"blocks"`
			Headers int64 `json:"headers"`
		}
		err := s.btcRPCClient().call(&chainInfo, "getblockchaininfo")
		if err == nil && chainInfo.Blocks < chainInfo.Headers-6 {
			err = fmt.Errorf("still syncing: block %d of %d", chainInfo.Blocks, chainInfo.Headers)
		}
		add("Bitcoin node", err, fmt.Sprintf("synced to block %d", chainInfo.Blocks))
	}
	pin := ""
	if card, err := readCard(filepath.Join(*dir, cardFileName)); err == nil {
		pin = card.TLSPin
		if *signerURL == "" {
			*signerURL = card.URL
		}
	}
	if *signerURL != "" && keyErr == nil && pin != "" {
		err := probeTLS(*signerURL, pin)
		add("signer service", err, "answering at "+*signerURL+" with its pinned transport key, and refusing clients without the coordinator's")
	} else if *signerURL != "" && keyErr == nil {
		// Unauthenticated, the signer should refuse; any answer shows it is up.
		r := &remoteSigner{URL: strings.TrimRight(*signerURL, "/")}
		err := r.status(&map[string]any{})
		switch {
		case err == nil:
			add("signer service", errors.New("answered without authentication"), "")
		case strings.Contains(err.Error(), "unauthorized"):
			add("signer service", nil, "answering at "+*signerURL+", and refusing unsigned requests")
		default:
			add("signer service", err, "")
		}
	}

	printJSON(results)
	for _, r := range results {
		if !r.OK {
			return errors.New("a check failed")
		}
	}
	return nil
}

// bitcoinRPCPort is Bitcoin Core's default RPC port on network.
func bitcoinRPCPort(network string) int {
	switch network {
	case "testnet":
		return 18332
	case "regtest":
		return 18443
	}
	return 8332
}
