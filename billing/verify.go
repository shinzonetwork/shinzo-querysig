package billing

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/shinzonetwork/shinzo-querysig/canonical"
)

// Request decodes the hex fields of e into the signed QueryRequest and the raw
// signature, so a verifier can recover the signer. It errors if any field is
// malformed (bad hex, wrong length).
func (e Extensions) Request() (QueryRequest, []byte, error) {
	queryHash, err := decodeHashBytes(e.QueryHash)
	if err != nil {
		return QueryRequest{}, nil, fmt.Errorf("query_hash: %w", err)
	}
	nonce, err := NonceFromHex(e.Nonce)
	if err != nil {
		return QueryRequest{}, nil, fmt.Errorf("nonce: %w", err)
	}
	pool, err := ParseAddress(e.PoolAddress)
	if err != nil {
		return QueryRequest{}, nil, fmt.Errorf("pool_address: %w", ErrInvalidPoolAddress)
	}
	sig, err := decodeHex(e.RequestSignature)
	if err != nil {
		return QueryRequest{}, nil, fmt.Errorf("request_signature: %w", err)
	}
	return QueryRequest{
		QueryHash: queryHash,
		Nonce:     nonce,
		Timestamp: e.RequestTimestamp,
		Pool:      pool,
	}, sig, nil
}

// VerifyRequest recomputes the query_hash from query and variables, confirms it
// matches the hash the client signed (so the query being served is the one that
// was authorized), recovers the payer from the request signature for chainID,
// and returns the payer address. ext is the signed envelope carried under the
// request's "extensions".
func VerifyRequest(chainID uint64, query string, variables json.RawMessage, ext Extensions) (Address, error) {
	req, sig, err := ext.Request()
	if err != nil {
		return Address{}, err
	}

	recomputed, _, err := canonical.QueryHash(query, variables)
	if err != nil {
		return Address{}, fmt.Errorf("recompute query hash: %w", err)
	}
	if req.QueryHash != recomputed {
		return Address{}, fmt.Errorf(
			"%w: signed %s, computed %s",
			ErrQueryHashMismatch, encodeHex(req.QueryHash[:]), encodeHex(recomputed[:]),
		)
	}

	return RecoverQueryRequest(chainID, req, sig)
}

// CheckFreshness rejects a request whose signed timestamp is more than maxAge
// from now in either direction, bounding how long a captured signature can be
// replayed: the QueryRequest binds no host and nothing tracks the nonce, so
// without this the signature never expires. The timestamp is signed, so it
// can't be altered without breaking recovery. A non-positive maxAge disables the
// check; now is passed in so the caller owns the clock.
func CheckFreshness(timestamp uint64, now time.Time, maxAge time.Duration) error {
	if maxAge <= 0 {
		return nil
	}
	if timestamp > math.MaxInt64 {
		return fmt.Errorf("%w: %d", ErrTimestampOutOfRange, timestamp)
	}
	signedAt := time.Unix(int64(timestamp), 0)
	if now.Sub(signedAt).Abs() > maxAge {
		return fmt.Errorf("%w: signed at %s, max age %s, now %s", ErrStaleTimestamp, signedAt.UTC(), maxAge, now.UTC())
	}
	return nil
}

// decodeHashBytes decodes a 0x-prefixed hex value and requires exactly 32 bytes.
func decodeHashBytes(s string) ([hashSize]byte, error) {
	b, err := decodeHex(s)
	if err != nil {
		return [hashSize]byte{}, err
	}
	if len(b) != hashSize {
		return [hashSize]byte{}, fmt.Errorf("%w: got %d", ErrInvalidHashLength, len(b))
	}
	var out [hashSize]byte
	copy(out[:], b)
	return out, nil
}
