## AERA Miner - Project Overview

### Architecture
- CLI utility with local keystore.
- Config in `config.toml` and status in `data/miner_status.json`.
- Keystore compatible with AERA Wallet.

### Modules
- `src/main.rs`: CLI and `init/import/start/stop/status` commands.
- `src/config.rs`: load and save `config.toml`.
- `src/state.rs`: miner status persistence.
- `src/wallet/keystore.rs`: compatible keystore and address derivation.

### Config & Schemas
- `config.toml`: base configuration.
- `schemas/config.schema.json`: config contract.
- `schemas/status.schema.json`: status contract.
