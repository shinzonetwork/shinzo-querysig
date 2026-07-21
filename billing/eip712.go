package billing

import "encoding/binary"

const (
	domainName    = "ShinzoQueryBilling"
	domainVersion = "1"

	domainType   = "EIP712Domain(string name,string version,uint256 chainId)"
	requestType  = "QueryRequest(bytes32 queryHash,bytes32 nonce,uint256 timestamp,address pool)"
	responseType = "QueryResponse(bytes32 queryHash,address host,address pool,uint256 rowsQueried,uint256 respondedAt,bytes32 responseCidsHash)"

	// wordSize is the width of an ABI-encoded EIP-712 word.
	wordSize = 32
)

// u256 encodes v as a big-endian EIP-712 word.
func u256(v uint64) []byte {
	b := make([]byte, wordSize)
	binary.BigEndian.PutUint64(b[wordSize-8:], v)
	return b
}

// word32 left-pads an address into an EIP-712 word.
func word32(a Address) []byte {
	b := make([]byte, wordSize)
	copy(b[wordSize-addressSize:], a[:])
	return b
}

// domainSeparator is the hash of the EIP-712 domain for chainID. There is no
// verifying contract, so the domain is (name, version, chainId).
func domainSeparator(chainID uint64) []byte {
	return keccak256(
		keccak256([]byte(domainType)),
		keccak256([]byte(domainName)),
		keccak256([]byte(domainVersion)),
		u256(chainID),
	)
}

// digest is the EIP-712 signing digest: keccak256(0x1901 || domain || struct).
func digest(chainID uint64, structHash []byte) []byte {
	return keccak256([]byte{0x19, 0x01}, domainSeparator(chainID), structHash)
}

// requestStructHash is the hashStruct of a QueryRequest.
func requestStructHash(req QueryRequest) []byte {
	return keccak256(
		keccak256([]byte(requestType)),
		req.QueryHash[:],
		req.Nonce[:],
		u256(req.Timestamp),
		word32(req.Pool),
	)
}

// responseStructHash is the hashStruct of a QueryResponse.
func responseStructHash(resp QueryResponse) []byte {
	return keccak256(
		keccak256([]byte(responseType)),
		resp.QueryHash[:],
		word32(resp.Host),
		word32(resp.Pool),
		u256(resp.RowsQueried),
		u256(resp.RespondedAt),
		resp.ResponseCidsHash[:],
	)
}
