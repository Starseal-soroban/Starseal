# Contributing to Starseal

Thanks for helping make Soroban smart accounts quantum-safe. This guide covers how to pick up work, set up the repo, and get a pull request merged.

## Picking up an issue

1. Find an open issue. Issues in a Drips Wave carry the `Stellar Wave` label and a complexity (Trivial, Medium or High).
2. Apply for Wave issues in the [Drips Wave app](https://www.drips.network/wave). For other issues, comment that you'd like to take it.
3. **Wait until a maintainer assigns you before you start.** Unassigned pull requests may be closed.
4. If you can't finish in time, say so in the issue as early as you can so it can be reassigned.

## Setting up

You need:

- Rust 1.91 or newer, with the `wasm32v1-none` target (`rustup target add wasm32v1-none`)
- [Stellar CLI](https://github.com/stellar/stellar-cli) 30 or newer, to build contracts (`stellar contract build`)
- Node.js 22 or newer and pnpm 10
- Docker, for the end-to-end and OpenBao tests

```sh
git clone https://github.com/Starseal-soroban/Starseal
cd Starseal
cargo test
pnpm install
pnpm test
```

## Making a change

- Branch from `main` with a short descriptive name, such as `feat/verifier-87` or `fix/sdk-digest-order`.
- Keep each pull request to one issue.
- Use [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`.
- Before pushing, run:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
pnpm lint
pnpm typecheck
pnpm test
```

## Opening a pull request

- Put `Closes #<issue number>` in the description so the issue closes when the PR merges.
- Explain what changed and how you tested it. Include command output or screenshots where they help.
- New behaviour needs tests. Bug fixes need a test that fails without the fix.
- CI must be green before review.

## Rules for cryptographic code

- **Never implement cryptography yourself.** On-chain verification uses the Soroban host functions; off-chain signing uses established libraries.
- **Don't change the signature format** (key commitment, `sig_data` layout or the `nido-mldsa-v1` context) without an issue discussed with the maintainers first. Other verifiers depend on it.
- Changes to signing or verification need test vectors: valid cases and tampered ones.

## Using AI tools

You can use AI assistants, but you are responsible for every line you submit. Pull requests with untested or unexplained generated code will be closed. Be ready to explain your change in review.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
