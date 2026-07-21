package billing

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// This file holds the Ethereum-flavored primitives the billing messages need,
// re-implemented on decred's secp256k1 and x/crypto/sha3 so the package carries
// no go-ethereum dependency. The wire format is unchanged: keccak256 hashing,
// 20-byte addresses printed with the EIP-55 checksum, and 65-byte recoverable
// signatures (r, s, v) with v as 27/28, matching viem and every EVM wallet.

const (
	addressSize = 20
	sigSize     = 65
	privKeySize = 32

	// recoveryIDOffset is the 27 added to a 0/1 recovery id to form the
	// wallet-style v (27/28) that viem and ecrecover use.
	recoveryIDOffset = 27
)

// Address is a 20-byte Ethereum account address.
type Address [addressSize]byte

// ParseAddress decodes a hex address with an optional 0x prefix. It requires
// exactly 20 bytes so a malformed value cannot be silently padded into a
// different address, and accepts any letter case (checksummed or not).
func ParseAddress(s string) (Address, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return Address{}, fmt.Errorf("decode address: %w", err)
	}
	if len(b) != addressSize {
		return Address{}, fmt.Errorf("%w: got %d bytes", ErrInvalidAddress, len(b))
	}
	return Address(b), nil
}

// mustAddress parses a known-good literal address and panics otherwise. It is
// for fixed constants and tests, never for wire input.
func mustAddress(s string) Address {
	a, err := ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

// Hex returns the address as 0x-prefixed hex with the EIP-55 mixed-case
// checksum, the canonical on-wire form. A hex letter is uppercased when the
// matching nibble of keccak256(lowercase hex) is >= 8.
func (a Address) Hex() string {
	const checksumOn = 8 // EIP-55 threshold: uppercase when the hash nibble is >= 8

	lower := hex.EncodeToString(a[:])
	hash := keccak256([]byte(lower))
	buf := []byte("0x" + lower)
	for i, c := range []byte(lower) {
		if c < 'a' || c > 'f' {
			continue // digits carry no case
		}
		if hashNibble(hash, i) >= checksumOn {
			buf[len("0x")+i] = c - ('a' - 'A')
		}
	}
	return string(buf)
}

// hashNibble returns the i-th 4-bit nibble of h: the high nibble of byte i/2 for
// even i, the low nibble for odd i.
func hashNibble(h []byte, i int) byte {
	const (
		nibbleBits = 4    // bits per hex digit
		nibbleMask = 0x0f // low nibble of a byte
	)
	b := h[i/2]
	if i%2 == 0 {
		return b >> nibbleBits
	}
	return b & nibbleMask
}

// String returns the checksummed hex form.
func (a Address) String() string { return a.Hex() }

// keccak256 returns the Keccak-256 (legacy, pre-NIST) hash of the concatenated
// parts, the hash EVM tooling and viem use.
func keccak256(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// encodeHex returns b as a 0x-prefixed lowercase hex string.
func encodeHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// decodeHex decodes a 0x-prefixed hex string. The prefix is required so a
// caller never mistakes raw text for hex; length is validated by the caller.
func decodeHex(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("%w: %q", ErrMissingHexPrefix, s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return b, nil
}

// sign returns a 65-byte recoverable signature (r, s, v) over digest, with v as
// 27/28. digest must be a 32-byte hash.
func sign(digest []byte, priv *secp256k1.PrivateKey) []byte {
	// SignCompact returns [v(27/28) || r || s] with a low-S canonical, RFC-6979
	// deterministic signature; move v to the tail for the r||s||v wire order.
	sig := dcrecdsa.SignCompact(priv, digest, false)
	return append(sig[1:], sig[0])
}

// recoverAddress returns the address that signed digest. It accepts a recovery
// id of 27/28 or 0/1 in the trailing byte.
func recoverAddress(digest, sig []byte) (Address, error) {
	if len(sig) != sigSize {
		return Address{}, fmt.Errorf("%w: got %d", ErrInvalidSignatureLength, len(sig))
	}
	v := sig[sigSize-1]
	if v < recoveryIDOffset {
		v += recoveryIDOffset
	}
	// RecoverCompact wants [v || r || s].
	compact := make([]byte, sigSize)
	compact[0] = v
	copy(compact[1:], sig[:sigSize-1])
	pub, _, err := dcrecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return Address{}, fmt.Errorf("recover signer: %w", err)
	}
	return pubkeyBytesToAddress(pub.SerializeUncompressed()), nil
}

// pubkeyBytesToAddress derives an address from a 65-byte uncompressed public key
// (0x04 || X || Y): keccak256 of the 64-byte body, low 20 bytes.
func pubkeyBytesToAddress(uncompressed []byte) Address {
	return Address(keccak256(uncompressed[1:])[12:])
}

// PubkeyToAddress derives the address of a secp256k1 public key.
func PubkeyToAddress(pub *secp256k1.PublicKey) Address {
	return pubkeyBytesToAddress(pub.SerializeUncompressed())
}

// KeyFromHex loads a secp256k1 private key from a hex-encoded 32-byte scalar,
// with or without a 0x prefix.
func KeyFromHex(s string) (*secp256k1.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != privKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPrivateKey, len(b))
	}
	return secp256k1.PrivKeyFromBytes(b), nil
}
