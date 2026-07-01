package billing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	// EIP-712 type and field names for the QueryResponse schema. These must
	// match the same literals the viem client signs against.
	eip712DomainType  = "EIP712Domain"
	queryResponseType = "QueryResponse"

	fieldName             = "name"
	fieldVersion          = "version"
	fieldChainID          = "chainId"
	fieldQueryHash        = "queryHash"
	fieldHost             = "host"
	fieldPool             = "pool"
	fieldRowsQueried      = "rowsQueried"
	fieldRespondedAt      = "respondedAt"
	fieldResponseCidsHash = "responseCidsHash"

	solidityString  = "string"
	solidityUint256 = "uint256"
	solidityAddress = "address"
	solidityBytes32 = "bytes32"

	// cidsHashSeparator joins sorted CIDs before hashing; see ResponseCidsHash.
	cidsHashSeparator = "\n"
)

// QueryResponse is the EIP-712 message a host signs to attest it served a query.
// The accounting service recovers the host from the signature. RespondedAt is in
// unix seconds; ResponseCidsHash commits to the source documents the host read.
type QueryResponse struct {
	QueryHash        [hashSize]byte
	Host             common.Address
	Pool             common.Address
	RowsQueried      uint64
	RespondedAt      uint64
	ResponseCidsHash [hashSize]byte
}

// SignQueryResponse signs resp for chainID with priv and returns a 65-byte
// signature (r, s, v) with v as 27/28.
func SignQueryResponse(chainID uint64, priv *ecdsa.PrivateKey, resp QueryResponse) ([]byte, error) {
	digest, err := responseDigest(chainID, resp)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.Sign(digest, priv)
	if err != nil {
		return nil, fmt.Errorf("sign query response: %w", err)
	}
	sig[sigSize-1] += sigVOffset
	return sig, nil
}

// RecoverQueryResponse returns the host address that signed resp for chainID. It
// accepts a recovery id of 27/28 or 0/1.
func RecoverQueryResponse(chainID uint64, resp QueryResponse, sig []byte) (common.Address, error) {
	if len(sig) != sigSize {
		return common.Address{}, fmt.Errorf("%w: got %d", ErrInvalidSignatureLength, len(sig))
	}
	digest, err := responseDigest(chainID, resp)
	if err != nil {
		return common.Address{}, err
	}
	normalized := make([]byte, sigSize)
	copy(normalized, sig)
	if normalized[sigSize-1] >= sigVOffset {
		normalized[sigSize-1] -= sigVOffset
	}
	pub, err := crypto.SigToPub(digest, normalized)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover query response signer: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// ResponseCidsHash returns keccak256 over the response's source CIDs, sorted and
// joined by newline. CIDs carry no newline, so the encoding is unambiguous; the
// host and accounting service must use this same encoding. The empty set hashes
// to a fixed value, so a v1 record with no CIDs is still well-defined.
func ResponseCidsHash(cids []string) [hashSize]byte {
	sorted := append([]string(nil), cids...)
	sort.Strings(sorted)
	var out [hashSize]byte
	copy(out[:], crypto.Keccak256([]byte(strings.Join(sorted, cidsHashSeparator))))
	return out
}

// responseDigest returns the EIP-712 signing digest for resp under chainID.
func responseDigest(chainID uint64, resp QueryResponse) ([]byte, error) {
	td := apitypes.TypedData{
		Types: apitypes.Types{
			eip712DomainType: {
				{Name: fieldName, Type: solidityString},
				{Name: fieldVersion, Type: solidityString},
				{Name: fieldChainID, Type: solidityUint256},
			},
			queryResponseType: {
				{Name: fieldQueryHash, Type: solidityBytes32},
				{Name: fieldHost, Type: solidityAddress},
				{Name: fieldPool, Type: solidityAddress},
				{Name: fieldRowsQueried, Type: solidityUint256},
				{Name: fieldRespondedAt, Type: solidityUint256},
				{Name: fieldResponseCidsHash, Type: solidityBytes32},
			},
		},
		PrimaryType: queryResponseType,
		Domain: apitypes.TypedDataDomain{
			Name:    domainName,
			Version: domainVersion,
			ChainId: (*math.HexOrDecimal256)(new(big.Int).SetUint64(chainID)),
		},
		Message: apitypes.TypedDataMessage{
			fieldQueryHash:        hexutil.Encode(resp.QueryHash[:]),
			fieldHost:             resp.Host.Hex(),
			fieldPool:             resp.Pool.Hex(),
			fieldRowsQueried:      (*math.HexOrDecimal256)(new(big.Int).SetUint64(resp.RowsQueried)),
			fieldRespondedAt:      (*math.HexOrDecimal256)(new(big.Int).SetUint64(resp.RespondedAt)),
			fieldResponseCidsHash: hexutil.Encode(resp.ResponseCidsHash[:]),
		},
	}
	digest, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("eip712 digest: %w", err)
	}
	return digest, nil
}
