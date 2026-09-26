package main

// Signer keys at rest. A key file holds the 32-byte key as hex, or that
// same text encrypted with age to a passphrase (scrypt), so a copy of the
// file (a backup, a disk image) is useless without the passphrase, and the
// operator can always decrypt it with the age tool alone. A running signer
// gets the passphrase from its systemd credential, which systemd-creds seals
// with the machine's TPM where there is one (and its host key otherwise);
// a command run by hand asks for it.
//
// Plain hex files, as every key was written before, still load, with a
// warning; "signer-key encrypt" encrypts one in place.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"

	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
)

// passphraseCredential is the systemd credential holding a signer's key
// passphrase (LoadCredentialEncrypted= in its unit).
const passphraseCredential = "signer-key-passphrase"

// passphraseEnv names a file holding the passphrase, for scripts.
const passphraseEnv = "BTCVM_KEY_PASSPHRASE_FILE"

func isEncryptedKey(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return bytes.HasPrefix(raw, []byte(armor.Header)) || bytes.HasPrefix(raw, []byte("age-encryption.org/"))
}

// keyPassphrase finds the passphrase for the encrypted key at path: from
// the file $BTCVM_KEY_PASSPHRASE_FILE names, the service's systemd
// credential, or the terminal.
func keyPassphrase(path string) (string, error) {
	if f := os.Getenv(passphraseEnv); f != "" {
		return readPassphraseFile(f)
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if p, err := readPassphraseFile(filepath.Join(dir, passphraseCredential)); err == nil {
			return p, nil
		}
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "Passphrase for %s: ", path)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(raw), err
	}
	return "", fmt.Errorf("%s is encrypted: give its passphrase in the %s systemd credential, or a file named by $%s",
		path, passphraseCredential, passphraseEnv)
}

func readPassphraseFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	p := strings.TrimRight(string(raw), "\r\n")
	if p == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return p, nil
}

// readKeyFile reads a signer's (or the coordinator's) private key, refusing
// a file other users can read.
func readKeyFile(path string) (*btcec.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; chmod 600 it", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isEncryptedKey(raw) {
		pass, err := keyPassphrase(path)
		if err != nil {
			return nil, err
		}
		if raw, err = decryptKey(raw, pass); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: %s holds its key unencrypted; encrypt it with signer-key encrypt (docs/SIGNERS.md)\n", path)
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(secret) != 32 {
		return nil, fmt.Errorf("%s must hold a 32-byte hex private key", path)
	}
	key, _ := btcec.PrivKeyFromBytes(secret)
	return key, nil
}

// encryptKey is plain (a key as hex) encrypted with age to passphrase,
// armored.
func encryptKey(plain []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("a key passphrase has at least 12 characters")
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	a := armor.NewWriter(&out)
	w, err := age.Encrypt(a, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := a.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decryptKey(raw []byte, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	var in io.Reader = bytes.NewReader(raw)
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte(armor.Header)) {
		in = armor.NewReader(bytes.NewReader(bytes.TrimSpace(raw)))
	}
	r, err := age.Decrypt(in, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting the key (wrong passphrase?): %w", err)
	}
	return io.ReadAll(io.LimitReader(r, 4096))
}

// newPassphrase asks for a new key passphrase twice, or reads it from the
// file $BTCVM_KEY_PASSPHRASE_FILE names.
func newPassphrase(p *prompter) (string, error) {
	if f := os.Getenv(passphraseEnv); f != "" {
		return readPassphraseFile(f)
	}
	if !p.interactive {
		return "", fmt.Errorf("an encrypted key needs a passphrase: set $%s to a file holding it, or pass -plaintext-key", passphraseEnv)
	}
	first, err := p.secret("Passphrase to encrypt the key with (12 characters or more; keep it with your offline backup)")
	if err != nil {
		return "", err
	}
	again, err := p.secret("The same passphrase again")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", errors.New("the passphrases differ")
	}
	return first, nil
}

// writeKey writes a new key file: encrypted to passphrase, or as plain hex
// if passphrase is empty.
func writeKey(path string, key *btcec.PrivateKey, passphrase string) error {
	data := []byte(hex.EncodeToString(key.Serialize()) + "\n")
	if passphrase != "" {
		var err error
		if data, err = encryptKey(data, passphrase); err != nil {
			return err
		}
	}
	if err := writeNew(path, data, 0o600); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// cmdSignerKeyEncrypt encrypts a plain key file in place.
func cmdSignerKeyEncrypt(args []string) error {
	fs := flag.NewFlagSet("signer-key encrypt", flag.ExitOnError)
	keyFile := fs.String("key-file", "", "the plain key file to encrypt in place")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := required(map[string]string{"key-file": *keyFile}); err != nil {
		return err
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	if isEncryptedKey(raw) {
		return fmt.Errorf("%s is already encrypted", *keyFile)
	}
	key, err := readKeyFile(*keyFile)
	if err != nil {
		return err
	}
	pass, err := newPassphrase(newPrompter(false))
	if err != nil {
		return err
	}
	sealed, err := encryptKey(raw, pass)
	if err != nil {
		return err
	}
	if check, err := decryptKey(sealed, pass); err != nil || !bytes.Equal(check, raw) {
		return errors.New("the encrypted key didn't decrypt back to the key; nothing was changed")
	}
	tmp := *keyFile + ".encrypting"
	if err := writeNew(tmp, sealed, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, *keyFile); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(filepath.Dir(*keyFile)); err != nil {
		return err
	}
	printJSON(map[string]string{"keyFile": *keyFile, "publicKey": hex.EncodeToString(key.PubKey().SerializeCompressed()),
		"next": "give the service its passphrase (docs/SIGNERS.md), and delete unencrypted copies of the key, including in backups"})
	return nil
}
