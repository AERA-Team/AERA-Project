## AERA Project

**AERA** is a next‑generation decentralized blockchain ecosystem with:

- a **Rust core node** (`aera-blockchain`),
- a **desktop wallet** built with **Tauri + TypeScript** (`aera-wallet`),
- a **CLI miner** compatible with the same keystore format (`aera-miner`).

This repository is a monorepo that contains everything needed to:

- run a full AERA node,
- use the desktop wallet to manage AERA and USDT on supported networks,
- mine and validate the network.

---

## Repository structure

- `aera-wallet/` – Tauri desktop wallet
  - UI (Vite + TypeScript + modern CSS)
  - Tauri backend, talking to the AERA core via Rust commands
  - docs and getting started:
    - `README.md`
    - `GETTING_STARTED.md`
    - `docs/API_TX_SEND.md`

- `aera-blockchain/` – AERA core node and wallet logic
  - consensus, P2P networking (libp2p), state storage (sled)
  - keystore implementation with Argon2id + AES‑256‑GCM
  - Tauri bridge used by the desktop wallet
  - see `aera-blockchain/README.md` for details

- `aera-miner/` – CLI miner
  - shares the same keystore format as the wallet
  - connects to a local or remote AERA node
  - see `aera-miner/README.md` for config and usage

---

## Quick start (developers)

Clone the repo:

```bash
git clone https://github.com/AERA-Team/AERA-Project.git
cd AERA-Project
```

### Desktop wallet (Tauri)

```bash
cd aera-wallet

npm install
npm run tauri dev
```

See `aera-wallet/GETTING_STARTED.md` for a full end‑user guide (creating/importing wallets, mining, cross‑chain flows).

### Core node

```bash
cd aera-blockchain

cargo check
cargo test        # some keystore tests are long‑running
cargo run         # run node binary (if configured)
```

### Miner

```bash
cd aera-miner

cargo build --release
.\target\release\aera-miner --help
```

---

## ⚠️ Disclaimer & Terms of Use

AERA‑Project is an **open‑source experimental startup**.  
All software in this repository is provided **“as is”**, without any warranty of any kind.

By building or using any component of this project, you agree that:

- **You are fully responsible for your own keys, passwords, mnemonics, and funds.**
- The AERA team and community contributors **do not accept any liability** for:
  - loss of funds, access, or data,
  - bugs, vulnerabilities, or protocol changes,
  - misconfiguration or user mistakes,
  - attacks by third parties (phishing, malware, fake “support”).
- There is **no guarantee** of profitability, uptime, or future compatibility with exchanges and third‑party services.

Always verify that you are using the official repository URL and never share your recovery phrase or private keys.

For more detailed disclaimers, see:

- `aera-wallet/README.md`
- `aera-blockchain/README.md`
- `aera-miner/README.md`

---

## Contributions & feedback

We welcome **constructive feedback and collaboration**:

- bug reports and security issues,
- ideas for protocol improvements and UX polish,
- pull requests that improve safety, performance, or documentation.

Please open an issue or PR with a clear description and a focused scope.

