package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignersSpeakPinnedMutualTLS(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	c := h.signers[0]

	signerDir, coordDir, strangerDir := t.TempDir(), t.TempDir(), t.TempDir()
	signerPin, err := makeTransportKey(signerDir, "signer")
	require.NoError(err)
	coordPin, err := makeTransportKey(coordDir, "coordinator")
	require.NoError(err)
	strangerPin, err := makeTransportKey(strangerDir, "stranger")
	require.NoError(err)
	load := func(dir string) (string, string) {
		return filepath.Join(dir, tlsCertName), filepath.Join(dir, tlsKeyName)
	}
	signerPair, _, err := loadTransportKey(load(signerDir))
	require.NoError(err)
	coordPair, _, err := loadTransportKey(load(coordDir))
	require.NoError(err)
	strangerPair, _, err := loadTransportKey(load(strangerDir))
	require.NoError(err)

	srv := httptest.NewUnstartedServer(c.handler())
	srv.TLS = signerTLS(signerPair, coordPin)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// The coordinator, with the set naming its transport key, reaches the
	// signer over TLS to its pinned key.
	h.b.signers.CoordinatorTLS = coordPin
	r := &remoteSigner{URL: srv.URL, Token: c.token, TLSPin: signerPin}
	h.b.cosigners = []*remoteSigner{r}
	require.NoError(h.b.secureCosigners(load(coordDir)))
	var status map[string]any
	require.NoError(r.status(&status))
	require.Equal(false, status["solvent"] == nil)

	// Anyone else presenting a certificate is refused by the signer...
	stranger := &remoteSigner{URL: srv.URL, Token: c.token, client: pinnedClient(strangerPair, signerPin)}
	require.Error(stranger.status(&status))
	// ...so is a client without one...
	require.NoError(probeTLS(srv.URL, signerPin), "the signer refuses a client without a certificate")
	// ...and the coordinator refuses a signer whose key isn't the pinned one.
	misdirected := &remoteSigner{URL: srv.URL, Token: c.token, client: pinnedClient(coordPair, strangerPin)}
	require.ErrorContains(misdirected.status(&status), "is not the pinned")
	require.ErrorContains(probeTLS(srv.URL, strangerPin), "is not the pinned")

	// The coordinator's own key must be the one the set names.
	h.b.signers.CoordinatorTLS = strangerPin
	require.ErrorContains(h.b.secureCosigners(load(coordDir)), "not the one the signer set names")
	h.b.signers.CoordinatorTLS = coordPin

	// Plain HTTP only to this machine; https only with a pin.
	for url, want := range map[string]string{
		"http://10.0.0.7:9700":    "only over https",
		"https://10.0.0.7:9700":   "no transport key pin",
		"http://127.0.0.1:9700":   "",
		"http://localhost:9700/x": "",
	} {
		h.b.cosigners = []*remoteSigner{{URL: url}}
		err := h.b.secureCosigners(load(coordDir))
		if want == "" {
			require.NoError(err, url)
		} else {
			require.ErrorContains(err, want, url)
		}
	}
}

func TestCardSignsItsTransportPin(t *testing.T) {
	require := require.New(t)
	set, err := newSignerSet(1, 1)
	require.NoError(err)
	key := set.privKeys[0]

	legacy := makeCard("Signer 1", "http://127.0.0.1:9701", "", key)
	require.NoError(legacy.verify(), "cards without a pin still verify")
	card := makeCard("Signer 1", "https://signer.example:9700", "aa", key)
	require.NoError(card.verify())
	card.TLSPin = "bb"
	require.Error(card.verify(), "the proof covers the pin")
	card.TLSPin = ""
	require.Error(card.verify(), "a pin can't be dropped either")

	// The set's fingerprint covers the coordinator's pin, and sets without
	// one keep theirs.
	fixed := fixedSet(t)
	before := fixed.fingerprint()
	fixed.CoordinatorTLS = "cc"
	require.NotEqual(before, fixed.fingerprint())
}

func TestInitMakesTransportKeyForHTTPS(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()
	require.ErrorContains(setupInit([]string{"-yes", "-dir", filepath.Join(dir, "a"), "-name", "A", "-url", "http://signer.example:9700"}),
		"never plain http")

	b := filepath.Join(dir, "b")
	require.NoError(setupInit([]string{"-yes", "-dir", b, "-name", "B", "-url", "https://signer.example:9700"}))
	raw, err := os.ReadFile(filepath.Join(b, cardFileName))
	require.NoError(err)
	var card operatorCard
	require.NoError(json.Unmarshal(raw, &card))
	require.NoError(card.verify())
	_, pin, err := loadTransportKey(filepath.Join(b, tlsCertName), filepath.Join(b, tlsKeyName))
	require.NoError(err)
	require.Equal(pin, card.TLSPin)
	_, err = openSigningLog(filepath.Join(b, signingLogKey))
	require.NoError(err, "the signing log is born with the key")
}
