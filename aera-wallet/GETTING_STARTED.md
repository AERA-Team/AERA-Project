# AERA Wallet — Getting Started

This guide explains how to run the wallet, mine, and use core features.

## Prerequisites

- Node.js + npm
- Rust (via rustup)
- Tauri prerequisites for your OS (Windows: MSVC Build Tools + WebView2)

## Run the Wallet (Tauri Dev)

From `aera-wallet`:

```bash
npm install
npm run tauri dev
```

## First-Time Use (In App)

1. Create or import a wallet.
2. Click **Initialize Node**.
3. You can now view balances, send transactions, and access mining.

## Mining in the UI

- Open the **Mining** tab.
- Click **Start Mining**.

## Mining with CLI (aera-miner)

From `aera-miner`:

```bash
cargo build --release
```

Create a wallet:

```bash
.\target\release\aera-miner init --password "pass"
```

Start mining:

```bash
.\target\release\aera-miner start --address "aera1..."
```

## API Base URL

When documentation shows an endpoint like `/tx/send`, use:

```
https://api.aera.network/v1/tx/send
```

## Notes

- TON support is currently disabled in this build.
- macOS users can build from source; prebuilt `.app/.dmg` is not provided yet.
