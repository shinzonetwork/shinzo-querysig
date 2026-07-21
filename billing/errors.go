package billing

import "errors"

// Sentinel errors wrapped by the dynamic, context-carrying errors this
// package returns, so callers can match on them with errors.Is.
var (
	ErrInvalidNonceLength     = errors.New("nonce must be 32 bytes")
	ErrInvalidSignatureLength = errors.New("signature must be 65 bytes")
	ErrInvalidHashLength      = errors.New("hash must be 32 bytes")
	ErrQueryHashMismatch      = errors.New("query_hash mismatch")
	ErrStaleTimestamp         = errors.New("request timestamp outside freshness window")
	ErrTimestampOutOfRange    = errors.New("request timestamp exceeds int64 range")
	ErrInvalidPoolAddress     = errors.New("pool_address must be a hex address")
	ErrInvalidAddress         = errors.New("address must be 20 bytes")
	ErrMissingHexPrefix       = errors.New("hex value must be 0x-prefixed")
	ErrInvalidPrivateKey      = errors.New("private key must be 32 bytes")
)
