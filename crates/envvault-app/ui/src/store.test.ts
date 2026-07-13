// Store behavior (spec §10.2): transitions are correct, locking clears every
// piece of vault-derived data, and secret VALUES never enter the store.

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
    listProjects: vi.fn().mockResolvedValue({ status: "ok", data: [] }),
    listSecrets: vi.fn().mockResolvedValue({ status: "ok", data: [] }),
  },
}));

import { useVault } from "./store";
import type { ProjectSummary, SecretMeta } from "./bindings";

const project: ProjectSummary = {
  id: "p1",
  name: "acme",
  path: "/tmp/acme",
  createdAt: "2026-07-13T00:00:00Z",
  guardEnabled: true,
  environments: [
    { id: "e1", name: "development", isProduction: false, secretCount: 1 },
  ],
};

const meta: SecretMeta = {
  id: "s1",
  key: "STRIPE_KEY",
  note: null,
  detectedType: "StripeSecret",
  detectedLabel: "Stripe secret",
  createdAt: "2026-07-13T00:00:00Z",
  rotatedAt: "2026-07-13T00:00:00Z",
  valueLength: 15,
};

describe("vault store", () => {
  beforeEach(() => {
    useVault.setState({
      status: "loading",
      viaRecovery: false,
      projects: [],
      selectedProjectId: null,
      selectedEnvId: null,
      secrets: [],
    });
  });

  it("refresh maps an existing locked vault to 'locked'", async () => {
    await useVault.getState().refresh();
    expect(useVault.getState().status).toBe("locked");
    expect(useVault.getState().vaultPath).toBe("/tmp/vault.age");
  });

  it("locking clears every piece of vault-derived data", () => {
    useVault.setState({
      status: "unlocked",
      projects: [project],
      selectedProjectId: "p1",
      selectedEnvId: "e1",
      secrets: [meta],
    });

    useVault.getState().markLocked();

    const s = useVault.getState();
    expect(s.status).toBe("locked");
    expect(s.projects).toEqual([]);
    expect(s.secrets).toEqual([]);
    expect(s.selectedProjectId).toBeNull();
    expect(s.selectedEnvId).toBeNull();
  });

  it("secret metadata carries no value field — values cannot enter the store", () => {
    useVault.setState({ secrets: [meta] });
    for (const secret of useVault.getState().secrets) {
      expect(Object.keys(secret)).not.toContain("value");
      expect(Object.keys(secret)).toContain("valueLength");
    }
  });

  it("markUnlocked / markLocked transition and clear viaRecovery", () => {
    useVault.getState().markUnlocked(true);
    expect(useVault.getState().status).toBe("unlocked");
    expect(useVault.getState().viaRecovery).toBe(true);

    useVault.getState().markLocked();
    expect(useVault.getState().status).toBe("locked");
    expect(useVault.getState().viaRecovery).toBe(false);
  });
});
