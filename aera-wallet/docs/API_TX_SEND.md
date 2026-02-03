# AERA Node API: Submit Transaction

Base URL: `https://api.aera.network`

The wallet uses this endpoint to submit signed native AERA or AERA USDT transactions when the node is reachable. If the request fails, the desktop app may fall back to local processing for native AERA only.

## POST /tx/send

Submit a signed transaction payload. The payload is built and signed by the wallet; the API validates and broadcasts the transaction.

### Request

- **Method:** `POST`
- **URL:** `https://api.aera.network/tx/send`
- **Content-Type:** `application/json`

#### Body (JSON)

| Field       | Type   | Description                          |
|------------|--------|--------------------------------------|
| `sender`   | string | AERA address (bech32-style, lowercase) |
| `recipient`| string | AERA address of the recipient        |
| `amount`   | string | Amount in base units (18 decimals)   |
| `asset`    | string | `"aera"` or `"usdt"`                  |
| `timestamp`| number | Unix timestamp (seconds)             |
| `signature`| string | Hex-encoded Ed25519 signature        |

Example:

```json
{
  "sender": "aera1...",
  "recipient": "aera1...",
  "amount": "1000000000000000000",
  "asset": "aera",
  "timestamp": 1700000000,
  "signature": "a1b2c3..."
}
```

### Response

- **Success (2xx):** JSON body with transaction hash or error message from the node.

| Field   | Type   | Description        |
|--------|--------|--------------------|
| `hash` | string | Transaction hash (optional) |
| `error`| string | Error message (optional)    |

Example success:

```json
{ "hash": "0x..." }
```

Example error:

```json
{ "error": "Insufficient balance" }
```

- **Client errors (4xx):** Invalid payload, bad signature, or validation failure.
- **Server errors (5xx):** Node or network failure; the wallet may retry or use local fallback for AERA-only.

### Notes

- Signature is computed over a canonical JSON representation of `recipient`, `amount`, `asset`, `sender`, and `timestamp` (without the `signature` field).
- Amount must be a string of base units (e.g. `"1000000000000000000"` for 1 AERA with 18 decimals).
- Local fallback: if the POST fails, the desktop app may process native AERA transactions locally when possible; AERA USDT and other assets require the node.
