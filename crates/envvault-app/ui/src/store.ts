// Global UI state. Rule (spec §4.3): this store NEVER holds a secret value,
// a password, or a recovery key — those live only in component-local state
// for exactly as long as they are on screen.

import { create } from "zustand";
import { commands } from "./bindings";

export type VaultUiStatus = "loading" | "no-vault" | "locked" | "unlocked";

interface VaultStore {
  status: VaultUiStatus;
  vaultPath: string;
  appVersion: string;
  viaRecovery: boolean;
  autoLockMinutes: number | null;
  refresh: () => Promise<void>;
  markLocked: () => void;
  markUnlocked: (viaRecovery: boolean) => void;
}

export const useVault = create<VaultStore>((set, get) => ({
  status: "loading",
  vaultPath: "",
  appVersion: "",
  viaRecovery: false,
  autoLockMinutes: null,

  refresh: async () => {
    const result = await commands.vaultStatus();
    if (result.status === "ok") {
      const s = result.data;
      set({
        status: !s.vaultExists ? "no-vault" : s.unlocked ? "unlocked" : "locked",
        vaultPath: s.vaultPath,
        appVersion: s.appVersion,
        viaRecovery: s.viaRecovery,
        autoLockMinutes: s.autoLockMinutes,
      });
    }
  },

  markLocked: () => set({ status: "locked", viaRecovery: false }),

  // Optimistic transition, then reconcile details (auto-lock setting, path)
  // from the backend — the single source of truth.
  markUnlocked: (viaRecovery) => {
    set({ status: "unlocked", viaRecovery });
    void get().refresh();
  },
}));
