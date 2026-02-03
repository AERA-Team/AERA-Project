## AERA Wallet (Desktop, Tauri)

The **AERA Wallet** is the official cross‑platform desktop application for interacting with the AERA network.
It provides a unified interface for:

- managing **native AERA** balances,
- sending and receiving **USDT** on supported networks (Ethereum ERC‑20, TRON TRC‑20, and AERA native USDT),
- monitoring basic network status (blocks, peers),
- controlling local mining (via the integrated miner / separate CLI).

The app is built with:

- **Frontend**: TypeScript, Vite, modern CSS (glassmorphism UI),
- **Desktop shell**: Tauri 2,
- **Backend**: Rust (`aera-blockchain` crate embedded via Tauri commands).

### Development (from `aera-wallet/`)

```bash
npm install

# Run the wallet in development mode (Vite + Tauri)
npm run tauri dev

# Type-check + unit tests
npm run lint
npm run test
```

For full end‑to‑end functionality (balances, mining, transactions), you should also run or initialize a node
through the wallet UI, which uses the `aera-blockchain` core under the hood.

See `GETTING_STARTED.md` for step‑by‑step usage instructions for end users.

---

## ⚠️ Disclaimer & Terms of Use

This wallet is part of an **open‑source experimental startup project**. It is provided **“as is”**, without any
warranty of any kind, express or implied.

By downloading, building, or using this wallet, **you agree to the following**:

- **You are fully responsible for your own keys, passwords, mnemonics, and funds.**
- The AERA team and community contributors **do not accept any liability** for:
  - loss of funds, access, or data,
  - bugs or vulnerabilities in the software,
  - misconfiguration or user mistakes,
  - any damage caused by third‑party services or malicious actors.
- There is **no guarantee** of uptime, profitability, or continued compatibility with exchanges, explorers,
  or third‑party infrastructure.

### Beware of scammers

- The AERA project is **open source**. Anyone can clone the code, recompile, or redistribute modified binaries.
- Treat any message that asks for your **mnemonic, private key, or password** as malicious.
- The AERA team will **never**:
  - ask you to share a recovery phrase,
  - ask you to send funds to a “support” address,
  - offer guaranteed investment returns.

If you are unsure whether you understand the risks of self‑custody and experimental software,
use the wallet only with **small test amounts** that you can afford to lose.

---

## Open‑Source Startup & Contributions

This project is developed as an **open‑source startup**. The roadmap and features are driven by:

- internal team initiative,
- community feedback,
- available time and resources.

We **welcome constructive proposals and collaboration**:

- UX / UI improvements,
- performance and security hardening,
- documentation and educational material,
- integrations with other tools and ecosystems.

If you want to help:

1. Open an issue describing your idea or problem.
2. Share as many concrete details as possible (use cases, risks, edge cases).
3. If you are comfortable with Rust/TypeScript, consider sending a PR with a focused change.

# AERA Blockchain & Unified Console 🛰️

**AERA** is a next-generation decentralized blockchain ecosystem. The **AERA Unified Console** is the official high-performance interface for interacting with the AERA network and performing cross-chain operations.

Built with a focus on reliability and security, the console leverages the power of **Rust** (core) and **Tauri** (cross-platform framework).

## ✨ What does AERA offer to users?

*   **⚡ Enterprise-Grade Security:** Your private keys are protected at the OS system level (Windows/macOS Keychain), minimizing theft risks.
*   **🌐 Unified Multi-chain Hub:** Manage all your assets in one place: native AERA, Ethereum, and TRON. Forget about switching between multiple wallets.
*   **💸 Seamless Transactions:** Send and receive AERA and USDT tokens on supported networks directly through the console.
*   **⚙️ Mining Infrastructure:** Gain transparent access to AERA network monitoring and mining pool management directly within the application.

## ⚙️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Interface** | TypeScript, HTML5, CSS3 |
| **System Core** | **Rust**, Tauri Framework |
| **Networking** | Async HTTP Clients (Reqwest), WebSockets |
| **Security** | AES-256-GCM Encryption, OS-level Key Storage (Keyring), Zeroize RAM |

## Quick Start (Development)

To compile the project from source:

```bash
# 1. Install dependencies
npm install

# 2. Run in development mode with hot reload
npm run tauri dev
```

## Getting Started Guide

See `GETTING_STARTED.md` for full setup, mining, and usage steps.

## Repository Structure

This repository is a monorepo:

- `aera-wallet` — Tauri desktop app (UI + Rust bridge).
- `aera-blockchain` — core node and wallet logic (Rust).
- `aera-miner` — CLI miner compatible with wallet keystore.
- `aera-wallet-website` — landing website.

## FAQ

**Do I need to run a node to use the wallet?**  
For full features (balances, mining, transactions), initialize the node inside the app.

**Can I build on macOS?**  
Yes, but you must build from source on a Mac (Tauri requires macOS for macOS builds).

**Is TON supported?**  
TON is currently disabled in this build.

## Notes

- TON support is currently disabled in this build.
- macOS users can build from source; prebuilt `.app/.dmg` is not provided yet.
