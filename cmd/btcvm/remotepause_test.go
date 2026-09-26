package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

func TestAnyOperatorPausesEverySigner(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	target := h.signers[0]
	setPath := filepath.Join(t.TempDir(), "signers.json")
	require.NoError(writeSetFile(setPath, target.b.signers))
	target.b.signers.path = setPath
	set := target.b.signers

	// Another operator signs a pause with their signer key and sends it.
	keyFile := filepath.Join(t.TempDir(), "signer.key")
	require.NoError(writeKey(keyFile, h.signers[1].key, ""))
	require.NoError(cmdPauseRemote(set, keyFile, h.servers[0].URL, "a key may have leaked"))
	p := target.b.paused()
	require.NotNil(p)
	require.Contains(p.Reason, "a key may have leaked")
	req := signRequest{Chain: chainBTCVM, Tx: encodeTx(wire.NewMsgTx(2)), Action: action{Kind: actionRelease}}
	_, _, _, err := target.check(req)
	require.ErrorContains(err, "paused")

	post := func(sp signedPause) int {
		body, _ := json.Marshal(sp)
		resp, err := http.Post(h.servers[0].URL+"/v1/pause", "application/json", bytes.NewReader(body))
		require.NoError(err)
		resp.Body.Close()
		return resp.StatusCode
	}
	// Only its own operator resumes it; a pause from before then is never
	// applied again.
	earlier := signPause(set, h.signers[2].key, "earlier", time.Now().Add(-time.Minute))
	require.NoError(cmdResume([]string{"-signers", setPath}))
	require.Nil(target.b.paused())
	require.Equal(http.StatusUnauthorized, post(earlier))

	// A stranger's key, a changed reason, or an old pause: refused.
	stranger, err := newSignerSet(1, 1)
	require.NoError(err)
	require.Equal(http.StatusUnauthorized, post(signPause(set, stranger.privKeys[0], "no", time.Now())))
	forged := signPause(set, h.signers[1].key, "stop", time.Now())
	forged.Reason = "something else"
	require.Equal(http.StatusUnauthorized, post(forged))
	require.Equal(http.StatusUnauthorized, post(signPause(set, h.signers[1].key, "old", time.Now().Add(-time.Hour))))
	require.Nil(target.b.paused())
	require.Equal(http.StatusOK, post(signPause(set, h.signers[2].key, "a fresh one", time.Now())))
	require.NotNil(target.b.paused())
}

func TestOperatorTransportKeyOnlyPauses(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	c := h.signers[0]
	setPath := filepath.Join(t.TempDir(), "signers.json")
	require.NoError(writeSetFile(setPath, c.b.signers))
	c.b.signers.path = setPath

	signerDir, coordDir, operatorDir := t.TempDir(), t.TempDir(), t.TempDir()
	signerPin, _ := makeTransportKey(signerDir, "signer")
	coordPin, _ := makeTransportKey(coordDir, "coordinator")
	operatorPin, _ := makeTransportKey(operatorDir, "operator")
	signerPair, _, err := loadTransportKey(filepath.Join(signerDir, tlsCertName), filepath.Join(signerDir, tlsKeyName))
	require.NoError(err)
	operatorPair, _, err := loadTransportKey(filepath.Join(operatorDir, tlsCertName), filepath.Join(operatorDir, tlsKeyName))
	require.NoError(err)
	c.coordinatorPin = coordPin
	srv := httptest.NewUnstartedServer(c.handler())
	srv.TLS = signerTLS(signerPair, coordPin, operatorPin)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	operator := pinnedClient(operatorPair, signerPin)
	resp, err := operator.Get(srv.URL + "/v1/status")
	require.NoError(err)
	resp.Body.Close()
	require.Equal(http.StatusForbidden, resp.StatusCode, "an operator's transport key reaches nothing but the pause")
	body, _ := json.Marshal(signPause(c.b.signers, h.signers[1].key, "over TLS", time.Now()))
	resp, err = operator.Post(srv.URL+"/v1/pause", "application/json", bytes.NewReader(body))
	require.NoError(err)
	resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
	require.NotNil(c.b.paused())
}
