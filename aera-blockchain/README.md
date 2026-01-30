# AERA Blockchain & Unified Console 🛰️

**AERA** is a next-generation decentralized blockchain ecosystem. The **AERA Unified Console** is the official high-performance interface for interacting with the AERA network and performing cross-chain operations.

Built with a focus on reliability and security, the console leverages the power of **Rust** (core) and **Tauri** (cross-platform framework).

## ✨ What does AERA offer to users?

*   **⚡ Enterprise-Grade Security:** Your private keys are protected at the OS system level (Windows/macOS Keychain), minimizing theft risks.
*   **🌐 Unified Multi-chain Hub:** Manage all your assets in one place: native AERA, Ethereum, TRON, and TON. Forget about switching between multiple wallets.
*   **💸 Seamless Transactions:** Send and receive AERA and USDT tokens on supported networks through the console.
*   **⚙️ Mining Infrastructure:** Gain transparent access to AERA network monitoring and mining pool management directly within the application.

## ⚙️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Interface** | TypeScript, HTML5, CSS3 |
| **System Core** | **Rust**, Tauri Framework |
| **Networking** | Async HTTP Clients (Reqwest), WebSockets |
| **Security** | AES-256-GCM Encryption, OS-level Key Storage (Keyring), Zeroize RAM |

## Quick Start (Development)

To compile the project from source (from the `aera-wallet` directory):

```bash
# 1. Install dependencies
npm install

# 2. Run in development mode with hot reload
npm run tauri dev
```
