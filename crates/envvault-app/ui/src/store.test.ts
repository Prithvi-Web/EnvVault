// Store behavior (spec §10.2): state transitions are correct and the store
// never holds secret material.

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./bindings", () => ({
  commands: {
    vaultStatus: vi.fn().mockResolvedValue({
      status: "ok",
      data: {
        appVersion: "0.1.0",
        vaultExists: true,
        unlocked: false,
        viaRecovery: false,
        vaultPath: "/tmp/vault.age",
        autoLockMinutes: 10,
      },
    }),
  },
  events: { vaultLockedEvent: { listen: vi.fn() } },
}));

import { useVault } from "./store";

describe("vault store", () => {
  beforeEach(() => {
    useVault.setState({ status: "loading", viaRecovery: false });
  });

  it("refresh maps an existing locked vault to 'locked'", async () => {
    await useVault.getState().refresh();
    expect(useVault.getState().status).toBe("locked");
    expect(useVault.getState().vaultPath).toBe("/tmp/vault.age");
  });

  it("markUnlocked / markLocked transition and clear viaRecovery", () => {
    useVault.getState().markUnlocked(true);
    expect(useVault.getState().status).toBe("unlocked");
    expect(useVault.getState().viaRecovery).toBe(true);

    useVault.getState().markLocked();
    expect(useVault.getState().status).toBe("locked");
    expect(useVault.getState().viaRecovery).toBe(false);
  });

  it("holds no secret material — ever", () => {
    const keys = Object.keys(useVault.getState()).map((k) => k.toLowerCase());
    for (const banned of ["password", "passphrase", "secret", "recoverykey", "value"]) {
      expect(keys.some((k) => k.includes(banned))).toBe(false);
    }
  });
});
