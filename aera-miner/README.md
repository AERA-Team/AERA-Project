## AERA Miner (CLI)

The **AERA Miner** is a minimal command‑line utility for Proof‑of‑Work style mining on the AERA network.
It is designed to be compatible with the AERA desktop wallet keystore and to run alongside a local AERA node.

### Compatibility

- Keystore format matches `aera-blockchain/src/wallet/keystore.rs`.
- Address derivation is identical to the AERA Wallet.
- Keystore is stored under `{data_dir}/keystore`.

### Configuration

`config.toml` in the miner project root:

```toml
data_dir = "./data"
node_url = "http://127.0.0.1:3030"
mining_address = ""
```

### Basic usage

Build (from `aera-miner/`):

```bash
cargo build --release
```

Create a new wallet:

```bash
.\target\release\aera-miner init
```

Start mining:

```bash
.\target\release\aera-miner start --address "aera1..."
```

For full command help:

```bash
.\target\release\aera-miner --help
```

---

## ⚠️ Disclaimer & Terms of Use

The miner is part of an **open‑source experimental startup project**. It is provided **“as is”** with **no warranty**
regarding correctness, profitability, or suitability for any particular purpose.

By running this miner, **you acknowledge and accept** that:

- Mining **does not guarantee any rewards**. Difficulty, rewards, and network rules may change over time.
- You are solely responsible for:
  - system security (OS hardening, malware protection),
  - power and hardware costs,
  - correct configuration of `node_url`, `data_dir`, and `mining_address`.
- The AERA team and contributors **are not liable** for:
  - hardware damage or wear,
  - increased electricity bills,
  - any loss of funds due to bugs, vulnerabilities, or misconfiguration.

Always verify that you are running binaries you built yourself from the **official open‑source repository**,
and never download “optimized miners” from untrusted sources.

---

## Open‑Source Project & Collaboration

This miner is maintained on a **best‑effort basis**. Features may evolve depending on:

- protocol changes in `aera-blockchain`,
- feedback from users and node operators,
- available time and interest from the community.

We welcome:

- bug reports and reproducible issues,
- reasonable feature requests (better metrics, more robust control, etc.),
- pull requests that keep the code simple, safe, and well‑documented.

