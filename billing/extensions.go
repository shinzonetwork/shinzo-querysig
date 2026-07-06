package billing

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/shinzonetwork/shinzo-querysig/canonical"
)

// Extensions is the signed envelope a client attaches under a GraphQL request's
// "extensions" field. The host recovers the payer from RequestSignature over the
// QueryRequest (QueryHash, Nonce, RequestTimestamp, PoolAddress) and recomputes
// QueryHash from the query and variables to confirm it was not swapped.
// RequestSignature, Nonce, RequestTimestamp, and PoolAddress then travel on the
// service record so the accounting service re-verifies the signature and bills
// the recovered payer against the signed pool. Fanout is the requested host
// fan-out the gateway reads to size the sample. PoolAddress is the pool the query
// bills to, signed into the QueryRequest so it cannot be swapped in transit.
// Field names are snake_case to match the service record.
type Extensions struct {
	RequestSignature string `json:"request_signature"`
	Nonce            string `json:"nonce"`
	QueryHash        string `json:"query_hash"`
	RequestTimestamp uint64 `json:"request_timestamp"`
	PoolAddress      string `json:"pool_address"`
	Fanout           int    `json:"fanout"`
}

// SignRequest builds the signed extensions for one query: it derives the
// canonical query_hash, draws a fresh nonce, and signs the QueryRequest with
// priv for chainID. timestamp is unix seconds, passed in so the caller owns the
// clock and tests stay deterministic.
func SignRequest(chainID uint64, priv *ecdsa.PrivateKey, query string, variables json.RawMessage, pool common.Address, fanout int, timestamp uint64) (Extensions, error) {
	hash, _, err := canonical.QueryHash(query, variables)
	if err != nil {
		return Extensions{}, fmt.Errorf("query hash: %w", err)
	}
	nonce, err := NewNonce()
	if err != nil {
		return Extensions{}, err
	}
	sig, err := SignQueryRequest(chainID, priv, QueryRequest{
		QueryHash: hash,
		Nonce:     nonce,
		Timestamp: timestamp,
		Pool:      pool,
	})
	if err != nil {
		return Extensions{}, err
	}
	return Extensions{
		RequestSignature: hexutil.Encode(sig),
		Nonce:            hexutil.Encode(nonce[:]),
		QueryHash:        hexutil.Encode(hash[:]),
		RequestTimestamp: timestamp,
		PoolAddress:      pool.Hex(),
		Fanout:           fanout,
	}, nil
}
