import { describe, expect, it } from "vitest";
import {
  DEFAULT_EXPIRY_HOURS,
  EXPIRY_OPTIONS,
  generateSharePassphrase,
  MIN_SHARE_PASSPHRASE_CHARS,
} from "./share";

describe("generateSharePassphrase", () => {
  it("matches the grouped format and clears the backend minimum", () => {
    for (let i = 0; i < 50; i++) {
      const p = generateSharePassphrase();
      expect(p).toMatch(/^[a-zA-Z2-9]{4}(-[a-zA-Z2-9]{4}){3}$/);
      expect(p.length).toBeGreaterThanOrEqual(MIN_SHARE_PASSPHRASE_CHARS);
    }
  });

  it("never contains lookalike characters", () => {
    for (let i = 0; i < 50; i++) {
      expect(generateSharePassphrase()).not.toMatch(/[0O1lI]/);
    }
  });

  it("is not repeating itself", () => {
    const seen = new Set(Array.from({ length: 20 }, generateSharePassphrase));
    expect(seen.size).toBe(20);
  });
});

describe("expiry options", () => {
  it("offers a no-expiry choice but does not default to it", () => {
    expect(EXPIRY_OPTIONS.some((o) => o.hours === null)).toBe(true);
    expect(DEFAULT_EXPIRY_HOURS).not.toBeNull();
    expect(EXPIRY_OPTIONS.some((o) => o.hours === DEFAULT_EXPIRY_HOURS)).toBe(true);
  });
});
