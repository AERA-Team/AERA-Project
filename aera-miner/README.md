## AERA Miner (CLI)

Minimal mining utility compatible with AERA Wallet.

### Compatibility
- Keystore format matches `aera-blockchain/src/wallet/keystore.rs`.
- Address derivation is identical to AERA Wallet.
- Keystore stored at `{data_dir}/keystore`.

### Configuration
`config.toml` in the project root:
```
data_dir = "./data"
node_url = "http://127.0.0.1:3030"
mining_address = ""
```

### Full Setup (From Scratch)
1) Build:
```
cargo build --release
```
2) Create a wallet:
```
.\target\release\aera-miner init --password "pass"
```
This prints `Address` and `Mnemonic`. Save the mnemonic securely.
3) Start mining:
```
.\target\release\aera-miner start --address "aera1..."
```

### CLI Usage
```
.\target\release\aera-miner init --password "<password>"
.\target\release\aera-miner import --mnemonic "<12 words>" --password "<password>"
.\target\release\aera-miner export --address "aera1..." --out ".\\wallet.json"
.\target\release\aera-miner start --address "aera1..."
.\target\release\aera-miner stop
.\target\release\aera-miner status
```

### Create Wallet
```
.\target\release\aera-miner init --password "<password>"
```
Result:
- `Mnemonic` (12 words) for recovery.
- `Address` for mining.

### Import Wallet
If you have a mnemonic:
```
.\target\release\aera-miner import --mnemonic "<12 words>" --password "<password>"
```

If you have a keystore file `wallet_<address>.json`:
1) Copy the file to `.\data\keystore\`
2) Start mining:
```
.\target\release\aera-miner start --address "aera1..."
```

### Run Miner
`start` runs mining in the current terminal. Stop by:
- `Ctrl+C`, or
- `.\target\release\aera-miner stop` in another terminal.

### Security Notes
- Passwords are never logged.
- Mnemonic is only printed during `init`.

