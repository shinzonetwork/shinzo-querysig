package billing

import (
	"sort"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// cidsHashSeparator joins sorted CIDs before hashing; see ResponseCidsHash.
const cidsHashSeparator = "\n"

// QueryResponse is the EIP-712 message a host signs to attest it served a query.
// The accounting service recovers the host from the signature. RespondedAt is in
// unix seconds; ResponseCidsHash commits to the source documents the host read.
type QueryResponse struct {
	QueryHash        [hashSize]byte
	Host             Address
	Pool             Address
	RowsQueried      uint64
	RespondedAt      uint64
	ResponseCidsHash [hashSize]byte
}

// SignQueryResponse signs resp for chainID with priv and returns a 65-byte
// signature (r, s, v) with v as 27/28.
func SignQueryResponse(chainID uint64, priv *secp256k1.PrivateKey, resp QueryResponse) []byte {
	return sign(digest(chainID, responseStructHash(resp)), priv)
}

// RecoverQueryResponse returns the host address that signed resp for chainID. It
// accepts a recovery id of 27/28 or 0/1.
func RecoverQueryResponse(chainID uint64, resp QueryResponse, sig []byte) (Address, error) {
	return recoverAddress(digest(chainID, responseStructHash(resp)), sig)
}

// ResponseCidsHash returns keccak256 over the response's source CIDs, sorted and
// joined by newline. CIDs carry no newline, so the encoding is unambiguous; the
// host and accounting service must use this same encoding. The empty set hashes
// to a fixed value, so a v1 record with no CIDs is still well-defined.
func ResponseCidsHash(cids []string) [hashSize]byte {
	sorted := append([]string(nil), cids...)
	sort.Strings(sorted)
	var out [hashSize]byte
	copy(out[:], keccak256([]byte(strings.Join(sorted, cidsHashSeparator))))
	return out
}
