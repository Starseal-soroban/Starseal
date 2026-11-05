# Starseal

Post-quantum signers for Soroban smart accounts.

Starseal lets an [OpenZeppelin smart account](https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account) on Stellar require an ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) signature. Verification runs on-chain through the ML-DSA host functions that Protocol 30 ("Bell") adds to Soroban. Signing keys can live in your app or in [OpenBao](https://openbao.org), a free, self-hosted key service.

> **Status: early development.** Nothing here is audited. Use testnet only.

## Why

- Stellar's Quantum Preparedness Plan starts with post-quantum authorization inside smart contracts. Protocol 30 adds `verify_sig_ml_dsa_44`, `_65` and `_87` ([CAP-87](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md)). Testnet upgraded on 3 Nov 2026; the mainnet vote is on 23 Nov 2026.
- The ML-DSA verifiers that already exist for OpenZeppelin accounts ([Perch](https://github.com/stellar-registry/perch), [nido](https://github.com/nidohq/nido)) run ML-DSA in contract code. Starseal uses the host functions instead and adds the signing side: an SDK, a CLI and key-service support.

## What's planned for v0.1

| Part | What it does | Status |
| --- | --- | --- |
| `contracts/mldsa-verifier` | OpenZeppelin-compatible verifier for ML-DSA-44, -65 and -87, using the host functions | In progress |
| `packages/sdk` | One signer interface with local and OpenBao backends; auth digest and signature encoding | Planned |
| `packages/cli` | `starseal keygen`, `key create`, `add-signer`, `sign`, `verify` | Planned |
| `examples/` | An ML-DSA-only rule; a passkey or Ed25519 signer plus ML-DSA, both required | Planned |

## Compatibility with Perch and nido

Starseal uses the same signature format as the Perch and nido verifiers, so one key and one signature work with any of them:

- The account stores the SHA-256 of the ML-DSA public key as the signer's key data (32 bytes).
- `sig_data` is the XDR of `{ public_key, signature }`.
- The signature is pure ML-DSA over the account's 32-byte auth digest, with the context string `nido-mldsa-v1`.

Thanks to both projects for defining the format.

## Repository layout

```text
contracts/
  mldsa-verifier/   Soroban verifier contract (Rust)
packages/
  sdk/              @starseal/sdk (TypeScript)
  cli/              @starseal/cli, the `starseal` command
examples/           End-to-end examples on testnet
test-vectors/       Signatures shared by the Rust and TypeScript tests
```

## Development

You need Rust 1.91 or newer with the `wasm32v1-none` target, [Stellar CLI](https://github.com/stellar/stellar-cli) 30 or newer, Node.js 22 or newer, and pnpm 10. soroban-sdk 30 only builds contracts through Stellar CLI 30+.

```sh
cargo test                       # contract tests
stellar contract build           # wasm build
pnpm install
pnpm test                        # TypeScript tests
```

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

[MIT](LICENSE)
