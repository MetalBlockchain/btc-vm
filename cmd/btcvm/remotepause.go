package main

// Remote pause. Any operator can pause every signer of the set, not just
// their own, without the coordinator: they sign a pause with their signer
// key and send it to each signer's /v1/pause. A signer applies a pause
// signed by a key of its set (or of a set it replaced), made within
// pauseSkew of its clock and after its operator last resumed it, by writing
// the same paused.json the local pause does. Only a signer's own operator
// resumes it, locally: a stolen operator key can stop the peg, never start
// it. Over TLS, a signer lets operators' transport keys (the pins on their
// cards) reach /v1/pause and nothing else.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2/ecdsa"
)

// pauseSkew is how far from a signer's clock a signed pause may be dated.
const pauseSkew = 10 * time.Minute

// signedPause is a pause an operator signed with their signer key.
type signedPause struct {
	Reason    string `json:"reason"`
	Time      int64  `json:"time"`      // unix seconds
	PublicKey string `json:"publicKey"` // hex, the operator's signer key
	Signature string `json:"signature"` // DER, hex
}

// pauseDigest binds a pause to the set it pauses, by its fingerprint.
func pauseDigest(set *signerSet, unix int64, pub, reason string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("btcvm pause v1\n%s\n%d\n%s\n%s", set.fingerprintHex(), unix, pub, reason)))
	return sum[:]
}

func signPause(set *signerSet, key *btcec.PrivateKey, reason string, now time.Time) signedPause {
	pub := hex.EncodeToString(key.PubKey().SerializeCompressed())
	sig := ecdsa.Sign(key, pauseDigest(set, now.Unix(), pub, reason))
	return signedPause{Reason: reason, Time: now.Unix(), PublicKey: pub, Signature: hex.EncodeToString(sig.Serialize())}
}

// verify checks p was signed by a key of set's lineage, recently, and after
// resumedAt.
func (p signedPause) verify(set *signerSet, now, resumedAt time.Time) error {
	if strings.TrimSpace(p.Reason) == "" || len(p.Reason) > 500 {
		return errors.New("a pause gives a reason, of at most 500 characters")
	}
	raw, err := hex.DecodeString(p.PublicKey)
	if err != nil {
		return err
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return err
	}
	if set.indexOf(pub) < 0 && set.retired(pub) == nil {
		return errors.New("the pause is not signed by a key of this signer set")
	}
	sigRaw, err := hex.DecodeString(p.Signature)
	if err != nil {
		return err
	}
	sig, err := ecdsa.ParseDERSignature(sigRaw)
	if err != nil || !sig.Verify(pauseDigest(set, p.Time, p.PublicKey, p.Reason), pub) {
		return errors.New("the pause's signature does not verify")
	}
	at := time.Unix(p.Time, 0)
	if d := now.Sub(at); d > pauseSkew || d < -pauseSkew {
		return errors.New("the pause is dated too far from this signer's clock")
	}
	// Pauses are dated to the second; one from the second of the resume is
	// applied, as pausing is the safe side.
	if !resumedAt.IsZero() && p.Time < resumedAt.Unix() {
		return errors.New("the pause was made before this signer was last resumed")
	}
	return nil
}

// handlePause applies a signed pause. It needs no coordinator signature:
// the pause is signed by an operator.
func (c *cosigner) handlePause(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fail := func(code int, err error) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	var p signedPause
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil {
		fail(http.StatusBadRequest, err)
		return
	}
	set := c.b.signers
	if set.path == "" {
		fail(http.StatusInternalServerError, errors.New("this signer's set has no file to pause"))
		return
	}
	var resumedAt time.Time
	if raw, err := os.ReadFile(resumedPath(set.path)); err == nil {
		var last pauseState
		if json.Unmarshal(raw, &last) == nil {
			resumedAt = last.Since
		}
	}
	if err := p.verify(set, time.Now(), resumedAt); err != nil {
		fail(http.StatusUnauthorized, err)
		return
	}
	who := operatorOf(set, p.PublicKey)
	if err := writePause(set.path, pauseState{Reason: fmt.Sprintf("paused by %s: %s", who, p.Reason), Since: time.Unix(p.Time, 0).UTC()}); err != nil {
		fail(http.StatusInternalServerError, err)
		return
	}
	c.b.logf("PAUSED by %s (%s): %s", who, p.PublicKey, p.Reason)
	_ = json.NewEncoder(w).Encode(map[string]any{"paused": true})
}

// operatorOf names the operator whose card holds pub, or the key itself.
func operatorOf(set *signerSet, pub string) string {
	for _, op := range set.Operators {
		if op.PublicKey == pub && op.Name != "" {
			return op.Name
		}
	}
	return "signer " + pub[:16]
}

// cmdPauseRemote signs a pause with this operator's signer key and sends it
// to signers: those at -remote, or every signer on the set's cards.
func cmdPauseRemote(set *signerSet, keyFile, remote, reason string) error {
	key, err := readKeyFile(keyFile)
	if err != nil {
		return err
	}
	if set.indexOf(key.PubKey()) < 0 && set.retired(key.PubKey()) == nil {
		return errors.New("this key is not in the signer set")
	}
	var urls []string
	if remote == "all" {
		for _, op := range set.Operators {
			urls = append(urls, op.URL)
		}
	} else {
		urls = strings.Split(remote, ",")
	}
	if len(urls) == 0 {
		return errors.New("no signers to pause: the set has no cards; name them with -remote URL,URL")
	}
	body, _ := json.Marshal(signPause(set, key, reason, time.Now()))
	results := map[string]string{}
	failed := 0
	for _, raw := range urls {
		u := strings.TrimRight(strings.TrimSpace(raw), "/")
		client := signerClient
		if parsed, err := url.Parse(u); err == nil && parsed.Scheme == "https" {
			pin := ""
			for _, op := range set.Operators {
				if strings.TrimRight(op.URL, "/") == u {
					pin = op.TLSPin
				}
			}
			cert, keyPath, ok := transportFiles(keyFile)
			if pin == "" || !ok {
				results[u] = "needs this operator's transport key (next to -key-file) and the signer's pin on its card"
				failed++
				continue
			}
			pair, _, err := loadTransportKey(cert, keyPath)
			if err != nil {
				results[u] = err.Error()
				failed++
				continue
			}
			client = pinnedClient(pair, pin)
		}
		resp, err := client.Post(u+"/v1/pause", "application/json", bytes.NewReader(body))
		if err != nil {
			results[u] = err.Error()
			failed++
			continue
		}
		answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			results[u] = strconv.Itoa(resp.StatusCode) + " " + strings.TrimSpace(string(answer))
			failed++
			continue
		}
		results[u] = "paused"
	}
	printJSON(results)
	if failed > 0 {
		return fmt.Errorf("%d of %d signers were not paused; pause them another way (each operator: btcvm pause -dir DIR)", failed, len(urls))
	}
	return nil
}

// pauseFlagsRemote adds the flags of a remote pause to fs.
func pauseFlagsRemote(fs *flag.FlagSet) (remote, keyFile *string) {
	remote = fs.String("remote", "", `pause signers remotely: "all" (every signer on the set's cards) or URL,URL; signed with -key-file`)
	keyFile = fs.String("key-file", "", "for -remote: your signer key, which signs the pause")
	return remote, keyFile
}
