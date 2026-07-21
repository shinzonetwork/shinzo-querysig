// Package billing signs and recovers the EIP-712 messages behind a billed
// query. A client signs a QueryRequest to prove it authorized (and pays for) a
// query; the host and accounting service recover the signer from the signature.
//
// The domain omits verifyingContract (there is no verifier contract). chainId
// binds a signature to one chain and must match across the signer and every
// verifier, so it is a parameter rather than a constant: the shinzohub EVM
// chain id is 91273003 local, 91273002 devnet. The browser client signs the
// same typed data with viem; the golden vector under testdata/golden gates that
// a viem signature recovers here.
package billing

import (
	"crypto/rand"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	hashSize  = 32
	nonceSize = 32
)

// QueryRequest is the EIP-712 message a client signs to authorize one billed
// query. Pool is the pool the query bills to, so the payer authorizes the pool
// it is charged against. Timestamp is unix seconds; Nonce is 32 random bytes
// that make each request unique so a signature cannot be replayed.
type QueryRequest struct {
	QueryHash [hashSize]byte
	Nonce     [nonceSize]byte
	Timestamp uint64
	Pool      Address
}

// NewNonce returns 32 cryptographically random bytes for QueryRequest.Nonce.
func NewNonce() ([nonceSize]byte, error) {
	var n [nonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		return [nonceSize]byte{}, fmt.Errorf("read nonce: %w", err)
	}
	return n, nil
}

// NonceFromHex decodes a 0x-prefixed hex nonce and requires exactly 32 bytes, so
// a malformed wire value cannot be padded into a different request silently.
func NonceFromHex(s string) ([nonceSize]byte, error) {
	b, err := decodeHex(s)
	if err != nil {
		return [nonceSize]byte{}, fmt.Errorf("decode nonce: %w", err)
	}
	if len(b) != nonceSize {
		return [nonceSize]byte{}, fmt.Errorf("%w: got %d", ErrInvalidNonceLength, len(b))
	}
	var n [nonceSize]byte
	copy(n[:], b)
	return n, nil
}

// SignQueryRequest signs req for chainID with priv and returns a 65-byte
// signature (r, s, v) with v as 27/28, matching wallet and viem output.
func SignQueryRequest(chainID uint64, priv *secp256k1.PrivateKey, req QueryRequest) []byte {
	return sign(digest(chainID, requestStructHash(req)), priv)
}

// RecoverQueryRequest returns the address that signed req for chainID. It
// accepts a recovery id of 27/28 or 0/1.
func RecoverQueryRequest(chainID uint64, req QueryRequest, sig []byte) (Address, error) {
	return recoverAddress(digest(chainID, requestStructHash(req)), sig)
}
