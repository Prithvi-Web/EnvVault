// Global UI state. Rule (spec §4.3): this store NEVER holds a secret value,
// a password, or a recovery key — those live only in component-local state
// for exactly as long as they are on screen. Locking clears everything.

import { create } from "zustand";
import {
  commands,
  type GuardFindingEvent,
  type ProjectSummary,
  type SecretMeta,
} from "./bindings";

export type VaultUiStatus = "loading" | "no-vault" | "locked" | "unlocked";

interface VaultStore {
  status: VaultUiStatus;
  vaultPath: string;
  appVersion: string;
  viaRecovery: boolean;
  autoLockMinutes: number | null;

  projects: ProjectSummary[];
  selectedProjectId: string | null;
  selectedEnvId: string | null;
  secrets: SecretMeta[];

  /** The most recent Guard finding, shown as a dismissible banner. */
  guardFinding: GuardFindingEvent | null;
  setGuardFinding: (f: GuardFindingEvent | null) => void;

  refresh: () => Promise<void>;
  markLocked: () => void;
  markUnlocked: (viaRecovery: boolean) => void;

  loadProjects: () => Promise<void>;
  selectProject: (id: string) => void;
  selectEnv: (id: string) => void;
  loadSecrets: () => Promise<void>;
}

export const useVault = create<VaultStore>((set, get) => ({
  status: "loading",
  vaultPath: "",
  appVersion: "",
  viaRecovery: false,
  autoLockMinutes: null,

  projects: [],
  selectedProjectId: null,
  selectedEnvId: null,
  secrets: [],
  guardFinding: null,

  setGuardFinding: (f) => set({ guardFinding: f }),

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

  // Locking drops every piece of vault-derived data from the UI.
  markLocked: () =>
    set({
      status: "locked",
      viaRecovery: false,
      projects: [],
      selectedProjectId: null,
      selectedEnvId: null,
      secrets: [],
      guardFinding: null,
    }),

  // Optimistic transition, then reconcile details (auto-lock setting, path)
  // from the backend — the single source of truth.
  markUnlocked: (viaRecovery) => {
    set({ status: "unlocked", viaRecovery });
    void get().refresh();
    void get().loadProjects();
  },

  loadProjects: async () => {
    const result = await commands.listProjects();
    if (result.status !== "ok") return;
    const projects = result.data;
    set({ projects });

    // Keep the selection valid; default to first project, first non-prod env.
    const state = get();
    const selected = projects.find((p) => p.id === state.selectedProjectId);
    if (!selected) {
      const first = projects[0];
      if (first) {
        get().selectProject(first.id);
      } else {
        set({ selectedProjectId: null, selectedEnvId: null, secrets: [] });
      }
      return;
    }
    const env = selected.environments.find((e) => e.id === state.selectedEnvId);
    if (!env) {
      const fallback =
        selected.environments.find((e) => !e.isProduction) ?? selected.environments[0];
      set({ selectedEnvId: fallback ? fallback.id : null, secrets: [] });
    }
    void get().loadSecrets();
  },

  selectProject: (id) => {
    const project = get().projects.find((p) => p.id === id);
    if (!project) return;
    const env =
      project.environments.find((e) => !e.isProduction) ?? project.environments[0];
    set({ selectedProjectId: id, selectedEnvId: env ? env.id : null, secrets: [] });
    void get().loadSecrets();
  },

  selectEnv: (id) => {
    set({ selectedEnvId: id, secrets: [] });
    void get().loadSecrets();
  },

  loadSecrets: async () => {
    const { selectedProjectId, selectedEnvId } = get();
    if (!selectedProjectId || !selectedEnvId) return;
    const result = await commands.listSecrets(selectedProjectId, selectedEnvId);
    if (result.status === "ok") {
      // Only metadata arrives here — values never do (see SecretMeta type).
      set({ secrets: result.data });
    }
  },
}));

/** Selector: the currently selected project, if any. */
export function useSelectedProject(): ProjectSummary | null {
  return useVault(
    (s) => s.projects.find((p) => p.id === s.selectedProjectId) ?? null,
  );
}
