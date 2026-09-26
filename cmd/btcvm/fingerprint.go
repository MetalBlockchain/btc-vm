package main

// Signer-set fingerprints. Operators read a set's fingerprint out to each
// other over a separate channel before joining, so it must identify the set
// completely: it is the whole SHA-256 of what they agree to, 256 bits,
// spelled as 24 words (11 bits each) so it can be read out and compared by
// people. The words are BIP39's English list, but a fingerprint is not a
// seed phrase and holds nothing secret. Its hex is accepted too. Sets made
// before showed the first 80 bits as hex; the hash itself is unchanged.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// fingerprintHash is the SHA-256 of everything the signers agree to.
func (s *signerSet) fingerprintHash() [32]byte {
	agreed, _ := json.Marshal(struct {
		Required       int            `json:"required"`
		PublicKeys     []string       `json:"publicKeys"`
		Networks       *setNetworks   `json:"networks"`
		Operators      []operatorCard `json:"operators"`
		CoordinatorKey string         `json:"coordinatorKey"`
		Policy         *pegPolicy     `json:"policy"`
		// Omitted when empty, so sets made before rotation, or before
		// transport keys, keep their fingerprint.
		Previous       []priorSet `json:"previous,omitempty"`
		CoordinatorTLS string     `json:"coordinatorTLS,omitempty"`
	}{s.Required, s.PublicKeys, s.Networks, s.Operators, s.CoordinatorKey, s.Policy, s.Previous, s.CoordinatorTLS})
	return sha256.Sum256(agreed)
}

// fingerprint is the set's fingerprint as 24 words joined by hyphens.
func (s *signerSet) fingerprint() string {
	return strings.Join(fingerprintWordsOf(s.fingerprintHash()), "-")
}

// fingerprintHex is the fingerprint as 64 hex characters.
func (s *signerSet) fingerprintHex() string {
	sum := s.fingerprintHash()
	return hex.EncodeToString(sum[:])
}

// shortFingerprint is the 80-bit form shown before; only to recognise it.
func (s *signerSet) shortFingerprint() string {
	h := s.fingerprintHex()
	return strings.Join([]string{h[0:4], h[4:8], h[8:12], h[12:16], h[16:20]}, "-")
}

// fingerprintWordsOf spells sum 11 bits a word, most significant first; the
// last word carries the remaining 3 bits.
func fingerprintWordsOf(sum [32]byte) []string {
	var words []string
	var acc, bits uint
	for _, b := range sum {
		acc = acc<<8 | uint(b)
		bits += 8
		for bits >= 11 {
			bits -= 11
			words = append(words, fingerprintWords[(acc>>bits)&0x7ff])
		}
	}
	if bits > 0 {
		words = append(words, fingerprintWords[(acc<<(11-bits))&0x7ff])
	}
	return words
}

var (
	notHex   = regexp.MustCompile(`[\s:-]`)
	notWords = regexp.MustCompile(`[^a-z]+`)
)

// checkFingerprint checks given, as someone typed or pasted it, is the
// set's fingerprint: its words or its hex, whatever the case or separators.
func (s *signerSet) checkFingerprint(given string) error {
	g := strings.ToLower(strings.TrimSpace(given))
	if g == s.shortFingerprint() {
		return fmt.Errorf("%s is the short fingerprint shown before; confirm the full one with the other operators: %s", given, s.fingerprint())
	}
	if h := notHex.ReplaceAllString(g, ""); len(h) == 64 {
		if h == s.fingerprintHex() {
			return nil
		}
	} else if strings.Join(strings.Fields(notWords.ReplaceAllString(g, " ")), "-") == s.fingerprint() {
		return nil
	}
	return fmt.Errorf("the set's fingerprint is %s, not %s: do not join", s.fingerprint(), given)
}
