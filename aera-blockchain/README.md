## AERA Blockchain Core

AERA is a next–generation decentralized blockchain ecosystem.  
This crate contains the **core node, consensus, networking, and wallet logic** for the AERA network.

The project is built in **Rust** with a focus on correctness and security, and is used both by the desktop wallet
(`aera-wallet`) and by standalone node / miner setups.

### Tech overview

- **Language / runtime**: Rust, Tokio
- **Consensus & types**: custom AERA block/transaction types with Ed25519 signatures
- **P2P networking**: libp2p (gossipsub, Kademlia, request–response)
- **Storage**: sled key–value store
- **Security**:
  - Ed25519 signatures for blocks and transactions
  - Argon2id + AES‑256‑GCM for keystore encryption (see `wallet/keystore.rs`)
  - Input validation on Tauri bridge and CLI boundaries

### Development

From the `aera-blockchain` directory:

```bash
cargo check        # fast type-check
cargo test         # run core unit tests (some keystore tests are long-running)
cargo run          # run the node binary (if configured)
```

This crate is also consumed by:

- `../aera-wallet/src-tauri` – Tauri backend for the desktop wallet
- `../aera-miner` – CLI miner that shares the same keystore format

---

## ⚠️ Disclaimer & Terms of Use

This project is an **open‑source experimental startup**. It is provided **“as is”, without any warranties**,
express or implied, including but not limited to fitness for a particular purpose or merchantability.

By building, running, or using any part of this codebase, **you acknowledge and agree** that:

- **You are solely responsible for your own keys, funds, and security practices.**
- **The maintainers and contributors are not liable for any loss of funds, data, or other damages** arising from:
  - software bugs or vulnerabilities,
  - misconfiguration,
  - user mistakes (lost mnemonic, leaked password, wrong address, etc.),
  - attacks by third parties (phishing, malware, social engineering, fake “support”).
- The codebase may change over time; breaking changes, migrations, and deprecations are possible.

Always treat any message, e‑mail, or DM that asks for your **mnemonic, private key, or password** as malicious.
The AERA team will **never** ask you to send secrets or funds to a “support” wallet.

If you do not fully understand the risks of using experimental blockchain software,
you **should not** use this project with significant real‑value funds.

---

## Open‑Source Project & Contributions

This repository is maintained on a **best‑effort basis** by a small team and community contributors.
Roadmap and features may evolve depending on the team’s capacity and community interest.

We **welcome constructive feedback and collaboration**:

- bug reports and security issues,
- suggestions for protocol or UX improvements,
- pull requests that improve safety, performance, or developer experience.

Before opening a PR, please:

1. Keep changes focused and well‑scoped.
2. Add or update tests where it makes sense.
3. Avoid introducing new external dependencies unless necessary.

