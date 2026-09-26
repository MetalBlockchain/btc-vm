package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintWordsAreBIP39English(t *testing.T) {
	sum := sha256.Sum256([]byte(strings.Join(fingerprintWords, "\n") + "\n"))
	require.Equal(t, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hex.EncodeToString(sum[:]))
}

func TestFingerprintIsTheWholeHash(t *testing.T) {
	require := require.New(t)
	set := fixedSet(t)
	fp := set.fingerprint()
	words := strings.Split(fp, "-")
	require.Len(words, 24, "256 bits, 11 a word")
	require.Len(set.fingerprintHex(), 64)

	// Every bit counts: sets whose hashes differ anywhere differ in words.
	var a, b [32]byte
	b[31] = 1
	require.NotEqual(fingerprintWordsOf(a), fingerprintWordsOf(b))
	b = [32]byte{}
	b[0] = 0x80
	require.NotEqual(fingerprintWordsOf(a), fingerprintWordsOf(b))

	// join takes the words or the hex, however typed.
	require.NoError(set.checkFingerprint(fp))
	require.NoError(set.checkFingerprint(strings.ToUpper(strings.Join(words, " "))))
	require.NoError(set.checkFingerprint(set.fingerprintHex()))
	h := set.fingerprintHex()
	require.NoError(set.checkFingerprint(h[:32] + ":" + h[32:]))
	// Not the short form, nor a near miss.
	require.ErrorContains(set.checkFingerprint(set.shortFingerprint()), "short fingerprint")
	require.ErrorContains(set.checkFingerprint(strings.Join(words[:23], "-")), "do not join")
	other := fixedSet(t)
	other.CoordinatorTLS = "cc"
	require.Error(set.checkFingerprint(other.fingerprint()))
	require.Error(set.checkFingerprint(other.fingerprintHex()))
}
