# shinzo-querysig

EIP-712 signing contract for Shinzo query billing, shared by the host, the app
framework, and the accounting service so all three produce and verify the same
signatures.

## Packages

- `billing`: the EIP-712 messages and their signing and recovery. A client signs
  a `QueryRequest` to authorize and pay for a query; a host signs a
  `QueryResponse` to attest it served one. It also defines the `Extensions`
  envelope a client attaches to a GraphQL request and the freshness check a
  verifier applies.
- `canonical`: RFC 8785 (JCS) canonicalization, used to derive the `query_hash`
  both messages bind to.

## Signing contract

Domain `ShinzoQueryBilling`, version `1`, bound to an EVM `chainId`, with no
verifying contract. Signatures are recoverable secp256k1, so a signer's address
is derived from the signature rather than transmitted.

- `QueryRequest` (queryHash, nonce, timestamp) recovers the payer.
- `QueryResponse` (queryHash, host, pool, rowsQueried, respondedAt,
  responseCidsHash) recovers the host.

The browser client signs the same typed data with viem; `billing/testdata/golden`
pins that a viem signature recovers here.

## Install

```sh
go get github.com/shinzonetwork/shinzo-querysig
```
