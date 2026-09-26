package main

// Transport security between the coordinator and remote signers: mutual
// TLS with pinned keys. Each signer and the coordinator has a transport key
// (P-256, with a self-signed certificate) made next to its signing key; the
// SHA-256 of its public key is its pin. A signer's pin is on its card and
// the coordinator's in the signer set, so both are covered by the set's
// fingerprint, which every operator checks. The coordinator talks to a
// signer beyond its own machine only over TLS to that signer's pinned key,
// and such a signer accepts only the pinned coordinator. Request signing
// (the coordinator key) still authenticates every request; TLS keeps
// requests and answers private and makes a signer unreachable to anyone
// without the coordinator's transport key.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Transport key files, next to a signer's or the coordinator's key.
const (
	tlsKeyName  = "tls.key"
	tlsCertName = "tls.crt"
)

// makeTransportKey writes a new transport key and certificate to dir and
// returns its pin. It never replaces existing files.
func makeTransportKey(dir, name string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(dir, tlsKeyName), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return "", err
	}
	if err := writeNew(filepath.Join(dir, tlsCertName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", err
	}
	cert, _ := x509.ParseCertificate(der)
	return spkiPin(cert), nil
}

// spkiPin is a certificate's pin: the SHA-256 of its public key, hex.
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// loadTransportKey reads a transport key pair and returns it with its pin,
// refusing a key file other users can read.
func loadTransportKey(certPath, keyPath string) (tls.Certificate, string, error) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return tls.Certificate{}, "", fmt.Errorf("%s is readable by other users; chmod 600 it", keyPath)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", err
	}
	pair.Leaf = leaf
	return pair, spkiPin(leaf), nil
}

// transportFiles returns the transport key pair next to keyFile, if both
// files are there.
func transportFiles(keyFile string) (cert, key string, ok bool) {
	dir := filepath.Dir(keyFile)
	cert, key = filepath.Join(dir, tlsCertName), filepath.Join(dir, tlsKeyName)
	_, errC := os.Stat(cert)
	_, errK := os.Stat(key)
	return cert, key, errC == nil && errK == nil
}

// pinned accepts a peer only if its certificate's key has pin. Certificates
// are self-signed, so the pin replaces chain and name checks.
func pinned(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("the peer presented no certificate")
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		if got := spkiPin(cert); got != pin {
			return fmt.Errorf("the peer's transport key %s is not the pinned %s", got, pin)
		}
		return nil
	}
}

// signerTLS is a signer's server configuration: its own certificate, and
// only the pinned coordinator as a client.
func signerTLS(own tls.Certificate, coordinatorPin string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{own},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinned(coordinatorPin),
	}
}

// pinnedClient is the coordinator's client for one signer: it presents the
// coordinator's certificate and accepts only the signer's pinned key.
func pinnedClient(own tls.Certificate, signerPin string) *http.Client {
	return &http.Client{
		Timeout: signerClient.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:            tls.VersionTLS13,
				Certificates:          []tls.Certificate{own},
				InsecureSkipVerify:    true, // replaced by the pin check
				VerifyPeerCertificate: pinned(signerPin),
			},
			TLSHandshakeTimeout: 30 * time.Second,
		},
	}
}

// isLoopback reports whether a host (a name or an IP, without port) is this
// machine.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// secureCosigners gives each remote signer its transport: plain HTTP only
// to this machine; beyond it, TLS to the signer's pinned key, presenting
// the coordinator's transport key, whose pin the set must name.
func (b *bridge) secureCosigners(certPath, keyPath string) error {
	var own *tls.Certificate
	for _, r := range b.cosigners {
		u, err := url.Parse(r.URL)
		if err != nil {
			return fmt.Errorf("signer %s: %w", r.URL, err)
		}
		switch {
		case u.Scheme == "https":
			if r.TLSPin == "" {
				return fmt.Errorf("signer %s: no transport key pin (its card's tlsPin)", r.URL)
			}
			if own == nil {
				if certPath == "" {
					return errors.New("signers over TLS need the coordinator's transport key: -coordinator-tls-cert and -coordinator-tls-key")
				}
				pair, pin, err := loadTransportKey(certPath, keyPath)
				if err != nil {
					return err
				}
				if pin != b.signers.CoordinatorTLS {
					return fmt.Errorf("the coordinator's transport key %s is not the one the signer set names (%q)", pin, b.signers.CoordinatorTLS)
				}
				own = &pair
			}
			r.client = pinnedClient(*own, r.TLSPin)
		case u.Scheme == "http" && isLoopback(u.Hostname()):
		default:
			return fmt.Errorf("signer %s: a signer beyond this machine is reached only over https, with its key pinned", r.URL)
		}
	}
	return nil
}

// probeTLS checks a signer at rawURL presents the transport key with pin
// and refuses a client without the coordinator's certificate.
func probeTLS(rawURL, pin string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true, // replaced by the pin check
		VerifyPeerCertificate: pinned(pin),
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// In TLS 1.3 the server's refusal of a client without a certificate
	// arrives after the handshake, on the first read.
	if _, err := conn.Write([]byte("GET /v1/status HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")); err == nil {
		_, err = conn.Read(make([]byte, 1))
		if err == nil {
			return errors.New("it answered a client without the coordinator's certificate")
		}
	}
	return nil
}
