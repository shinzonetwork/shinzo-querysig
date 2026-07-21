package billing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCheckFreshness covers the replay-bounding window: a timestamp inside the
// window passes, one too old or too far in the future is rejected, and a
// non-positive maxAge disables the check.
func TestCheckFreshness(t *testing.T) {
	now := time.Unix(1735689600, 0)
	const maxAge = 2 * time.Minute

	cases := []struct {
		name    string
		ts      uint64
		maxAge  time.Duration
		wantErr bool
	}{
		{"within window", uint64(now.Add(-time.Minute).Unix()), maxAge, false},                  //nolint:gosec // test time is always small and positive
		{"exactly now", uint64(now.Unix()), maxAge, false},                                      //nolint:gosec // test time is always small and positive
		{"slightly future within skew", uint64(now.Add(time.Minute).Unix()), maxAge, false},     //nolint:gosec // test time is always small and positive
		{"too old", uint64(now.Add(-time.Hour).Unix()), maxAge, true},                           //nolint:gosec // test time is always small and positive
		{"too far future", uint64(now.Add(time.Hour).Unix()), maxAge, true},                     //nolint:gosec // test time is always small and positive
		{"disabled lets a stale request through", uint64(now.Add(-time.Hour).Unix()), 0, false}, //nolint:gosec // test time is always small and positive
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFreshness(tc.ts, now, tc.maxAge)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

// TestVerifyRequestRecoversPayer signs a request and confirms VerifyRequest
// recomputes the matching hash and recovers the signer as the payer.
func TestVerifyRequestRecoversPayer(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := PubkeyToAddress(priv.PubKey())
	const chainID = 91273002
	query := "query { Log { id } }"
	vars := json.RawMessage(`{"limit":10}`)

	ext, err := SignRequest(chainID, priv, query, vars, testPool, 3, 1735689600)
	if err != nil {
		t.Fatal(err)
	}

	payer, err := VerifyRequest(chainID, query, vars, ext)
	if err != nil {
		t.Fatal(err)
	}
	if payer != signer {
		t.Errorf("recovered %s, want %s", payer, signer)
	}
}

// TestVerifyRequestRejectsTamperedQuery checks that serving a different query
// than the one signed fails the hash binding.
func TestVerifyRequestRejectsTamperedQuery(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ext, err := SignRequest(91273002, priv, "query { A }", nil, testPool, 1, 1735689600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(91273002, "query { B }", nil, ext); err == nil {
		t.Fatal("expected a query_hash mismatch error, got nil")
	}
}

// TestVerifyRequestRejectsTamperedVariables checks the variables are bound into
// the hash, not just the query text.
func TestVerifyRequestRejectsTamperedVariables(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ext, err := SignRequest(91273002, priv, "query { A }", json.RawMessage(`{"limit":10}`), testPool, 1, 1735689600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(91273002, "query { A }", json.RawMessage(`{"limit":11}`), ext); err == nil {
		t.Fatal("expected a query_hash mismatch error for changed variables, got nil")
	}
}

// TestVerifyRequestWrongChainDoesNotRecoverSigner checks the chain id is part of
// the digest: verifying under a different chain recovers a different address, so
// a signature cannot be replayed onto another chain.
func TestVerifyRequestWrongChainDoesNotRecoverSigner(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := PubkeyToAddress(priv.PubKey())
	ext, err := SignRequest(91273002, priv, "query { A }", nil, testPool, 1, 1735689600)
	if err != nil {
		t.Fatal(err)
	}

	payer, err := VerifyRequest(91273003, "query { A }", nil, ext)
	if err != nil {
		t.Fatal(err)
	}
	if payer == signer {
		t.Error("a signature for chain 91273002 recovered the signer under chain 91273003")
	}
}

// TestVerifyRequestBindsPool checks the pool_address is part of the signed
// request: verifying an envelope whose pool_address was swapped after signing
// recovers a different address, so a host cannot be redirected to bill a pool
// the payer never authorized.
func TestVerifyRequestBindsPool(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := PubkeyToAddress(priv.PubKey())
	query := "query { A }"

	ext, err := SignRequest(91273002, priv, query, nil, testPool, 1, 1735689600)
	if err != nil {
		t.Fatal(err)
	}
	ext.PoolAddress = mustAddress("0x3333333333333333333333333333333333333333").Hex()

	payer, err := VerifyRequest(91273002, query, nil, ext)
	if err != nil {
		t.Fatal(err)
	}
	if payer == signer {
		t.Error("swapping pool_address still recovered the signer; pool is not bound into the request")
	}
}

func TestExtensionsRequestRejectsMalformed(t *testing.T) {
	hash32 := "0x" + strings.Repeat("00", 32)
	sig65 := "0x" + strings.Repeat("11", 65)
	pool := testPool.Hex()
	cases := []struct {
		name string
		ext  Extensions
	}{
		{"short query_hash", Extensions{RequestSignature: sig65, Nonce: hash32, QueryHash: "0x00", PoolAddress: pool}},
		{"short nonce", Extensions{RequestSignature: sig65, Nonce: "0x00", QueryHash: hash32, PoolAddress: pool}},
		{"bad signature hex", Extensions{RequestSignature: "0xzz", Nonce: hash32, QueryHash: hash32, PoolAddress: pool}},
		{"bad pool_address", Extensions{RequestSignature: sig65, Nonce: hash32, QueryHash: hash32, PoolAddress: "not-an-address"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := tc.ext.Request(); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
