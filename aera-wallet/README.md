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
