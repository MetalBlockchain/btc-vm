package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignerKeysAreEncryptedAtRest(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()
	set, err := newSignerSet(1, 1)
	require.NoError(err)
	key := set.privKeys[0]
	passFile := filepath.Join(dir, "passphrase")
	require.NoError(os.WriteFile(passFile, []byte("correct horse battery staple\n"), 0o600))
	t.Setenv(passphraseEnv, passFile)

	// A key as every signer has it today: plain hex. It still loads.
	path := filepath.Join(dir, "signer.key")
	require.NoError(writeKey(path, key, ""))
	loaded, err := readKeyFile(path)
	require.NoError(err)
	require.True(loaded.PubKey().IsEqual(key.PubKey()))

	// Encrypted in place, it holds no trace of the key and loads with the
	// passphrase alone.
	require.NoError(cmdSignerKeyEncrypt([]string{"-key-file", path}))
	sealed, err := os.ReadFile(path)
	require.NoError(err)
	require.True(isEncryptedKey(sealed))
	require.NotContains(string(sealed), hex.EncodeToString(key.Serialize()))
	info, err := os.Stat(path)
	require.NoError(err)
	require.Equal(os.FileMode(0o600), info.Mode().Perm())
	loaded, err = readKeyFile(path)
	require.NoError(err)
	require.True(loaded.PubKey().IsEqual(key.PubKey()))
	require.ErrorContains(cmdSignerKeyEncrypt([]string{"-key-file", path}), "already encrypted")

	// A running signer finds it in its systemd credential.
	t.Setenv(passphraseEnv, "")
	creds := t.TempDir()
	require.NoError(os.WriteFile(filepath.Join(creds, passphraseCredential), []byte("correct horse battery staple"), 0o600))
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	loaded, err = readKeyFile(path)
	require.NoError(err)
	require.True(loaded.PubKey().IsEqual(key.PubKey()))

	// The wrong passphrase, or none: refused.
	require.NoError(os.WriteFile(filepath.Join(creds, passphraseCredential), []byte("the wrong passphrase"), 0o600))
	_, err = readKeyFile(path)
	require.ErrorContains(err, "wrong passphrase")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	_, err = readKeyFile(path)
	require.ErrorContains(err, "is encrypted")

	// Short passphrases are refused.
	_, err = encryptKey([]byte("00"), "short")
	require.Error(err)
}
