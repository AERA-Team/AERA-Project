import { describe, it, expect } from "vitest";
import { CHAIN_DECIMALS, encodeAmount } from "./utils";

describe("CHAIN_DECIMALS", () => {
  it("has expected networks", () => {
    expect(CHAIN_DECIMALS.aera).toBe(18);
    expect(CHAIN_DECIMALS.aera_usdt).toBe(18);
    expect(CHAIN_DECIMALS.eth).toBe(18);
    expect(CHAIN_DECIMALS.bridge_eth).toBe(6);
    expect(CHAIN_DECIMALS.tron).toBe(6);
    expect(CHAIN_DECIMALS.tron_native).toBe(6);
  });
});

describe("encodeAmount", () => {
  it("encodes whole AERA amount", () => {
    expect(encodeAmount(1, "aera")).toBe("1000000000000000000");
    expect(encodeAmount(0, "aera")).toBe("0");
  });

  it("uses 18 decimals for aera network", () => {
    expect(encodeAmount(1.5, "aera")).toBe("1500000000000000000");
  });

  it("uses 6 decimals for bridge_eth (USDT)", () => {
    expect(encodeAmount(1, "bridge_eth")).toBe("1000000");
    expect(encodeAmount(0.000001, "bridge_eth")).toBe("1");
  });

  it("falls back to 18 decimals for unknown network", () => {
    expect(encodeAmount(1, "unknown")).toBe("1000000000000000000");
  });

  it("rounds fractional part to network decimals", () => {
    const sixDec = encodeAmount(1.123456, "bridge_eth");
    expect(sixDec).toBe("1123456");
  });
});
