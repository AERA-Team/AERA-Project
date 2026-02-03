/** Decimals per chain for amount encoding (base units) */
export const CHAIN_DECIMALS: { [k: string]: number } = {
    aera: 18,
    aera_usdt: 18,
    eth: 18,
    bridge_eth: 6,
    tron: 6,
    tron_native: 6,
};

/**
 * Encode a human-readable amount to base-unit string for a given network.
 * Uses the network's decimal count; falls back to 18 if unknown.
 */
export function encodeAmount(amount: number, network: string): string {
    const dec = CHAIN_DECIMALS[network] ?? 18;
    const mult = BigInt(10) ** BigInt(dec);
    const [w, f = ""] = amount.toFixed(Math.min(dec, 18)).split(".");
    const frac = f.padEnd(dec, "0").slice(0, dec);
    const base = BigInt(w || "0") * mult + BigInt(frac || "0");
    return base.toString();
}
