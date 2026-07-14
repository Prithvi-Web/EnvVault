// Pure helpers for Secure Share (spec F8). No IPC here — testable in vitest.

/**
 * Passphrase alphabet without lookalikes (no 0/O, 1/l/I) so a passphrase
 * read aloud over a call survives the trip. 54 symbols.
 */
const ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";

/**
 * Generate a grouped random passphrase like `x7Kd-9mQp-2rTv-8wZn`.
 * 16 symbols of a 54-symbol alphabet ≈ 92 bits of entropy — far past the
 * 12-character minimum the backend enforces. Uses rejection sampling so
 * every symbol is uniform (no modulo bias).
 */
export function generateSharePassphrase(): string {
  const symbols: string[] = [];
  while (symbols.length < 16) {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    for (const byte of buf) {
      if (symbols.length >= 16) break;
      // 216 = 4 × 54: accepting only bytes below keeps the modulo uniform.
      if (byte < 216) symbols.push(ALPHABET.charAt(byte % ALPHABET.length));
    }
  }
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 4) {
    groups.push(symbols.slice(i, i + 4).join(""));
  }
  return groups.join("-");
}

/** Minimum passphrase length — mirrors `MIN_SHARE_PASSPHRASE_CHARS` in core. */
export const MIN_SHARE_PASSPHRASE_CHARS = 12;

export interface ExpiryOption {
  label: string;
  hours: number | null;
}

/** Expiry choices for a bundle. Default is 7 days — a guardrail by default. */
export const EXPIRY_OPTIONS: ExpiryOption[] = [
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
  { label: "No expiry", hours: null },
];

export const DEFAULT_EXPIRY_HOURS = 24 * 7;
