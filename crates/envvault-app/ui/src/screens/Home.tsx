// The unlocked shell: sidebar of projects, environment tabs (production in
// red, always), the secrets table, and every action reachable from the
// keyboard: ⌘K palette, N new secret, / search, ⌘L lock.

import { useEffect, useRef, useState } from "react";
import {
  Activity,
  FileWarning,
  KeyRound,
  LockOpen,
  Plus,
  Search,
  Share2,
  Shield,
  ShieldOff,
} from "lucide-react";
import {
  commands,
  type EnvFileCandidate,
  type EnvironmentSummary,
  type ProjectSummary,
  type SecretMeta,
} from "../bindings";
import { useVault, useSelectedProject } from "../store";
import { describeError } from "../lib/errors";
import { loadScorer, scorePassword, REQUIRED_SCORE, type Strength } from "../lib/password";
import { Button, StrengthMeter, TextField } from "../ui/components";
import { ConfirmDialog } from "../ui/dialog";
import { Toasts, useToasts } from "../ui/toast";
import { Sidebar } from "./home/Sidebar";
import { EnvTabs } from "./home/EnvTabs";
import { SecretsTable } from "./home/SecretsTable";
import { SecretDialog, type SecretDialogMode } from "./home/SecretDialog";
import { ImportDialog } from "./home/ImportDialog";
import { GuardBanner } from "./home/GuardBanner";
import { HealthDashboard } from "./home/HealthDashboard";
import { AddProjectDialog } from "./home/AddProjectDialog";
import { AddEnvDialog } from "./home/AddEnvDialog";
import { CommandPalette } from "./home/CommandPalette";
import { ShareDialog } from "./home/ShareDialog";
import { ImportBundleDialog } from "./home/ImportBundleDialog";
import { VaultBackupDialog } from "./home/VaultBackupDialog";
import { ShareKeyDialog } from "./home/ShareKeyDialog";
import { AboutDialog } from "./home/AboutDialog";

export default function Home() {
  const { viaRecovery, autoLockMinutes, appVersion, refresh, markLocked, loadProjects } =
    useVault();
  const project = useSelectedProject();
  const selectedEnvId = useVault((s) => s.selectedEnvId);
  const loadSecrets = useVault((s) => s.loadSecrets);
  const guardFinding = useVault((s) => s.guardFinding);
  const setGuardFinding = useVault((s) => s.setGuardFinding);
  const selectProject = useVault((s) => s.selectProject);
  const push = useToasts((s) => s.push);

  const env = project?.environments.find((e) => e.id === selectedEnvId) ?? null;

  const [filter, setFilter] = useState("");
  const [secretDialog, setSecretDialog] = useState<SecretDialogMode | null>(null);
  const [addProjectOpen, setAddProjectOpen] = useState(false);
  const [addEnvOpen, setAddEnvOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [deleteSecret, setDeleteSecret] = useState<SecretMeta | null>(null);
  const [deleteProject, setDeleteProject] = useState<ProjectSummary | null>(null);
  const [deleteEnv, setDeleteEnv] = useState<EnvironmentSummary | null>(null);
  const [envFiles, setEnvFiles] = useState<EnvFileCandidate[]>([]);
  const [importFiles, setImportFiles] = useState<EnvFileCandidate[] | null>(null);
  const [guardEnabled, setGuardEnabled] = useState(true);
  const [view, setView] = useState<"secrets" | "health">("secrets");
  const [shareOpen, setShareOpen] = useState(false);
  const [importBundleOpen, setImportBundleOpen] = useState(false);
  const [backupOpen, setBackupOpen] = useState(false);
  const [shareKeyOpen, setShareKeyOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void commands.guardStatus().then((r) => {
      if (r.status === "ok") setGuardEnabled(r.data.enabled);
    });
  }, []);

  async function toggleGuard() {
    const next = !guardEnabled;
    setGuardEnabled(next);
    const r = await commands.setGuardEnabled(next);
    if (r.status === "error") {
      setGuardEnabled(!next); // revert on failure
      push(describeError(r.error));
    }
  }

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  // Watch for plaintext env files whenever the selected project changes.
  async function rescanEnvFiles(projectId: string | null | undefined) {
    if (!projectId) {
      setEnvFiles([]);
      return;
    }
    const result = await commands.scanEnvFiles(projectId);
    setEnvFiles(result.status === "ok" ? result.data : []);
  }

  useEffect(() => {
    void rescanEnvFiles(project?.id);
  }, [project?.id]);

  useEffect(() => {
    setFilter("");
  }, [project?.id, selectedEnvId]);

  const modalOpen =
    secretDialog !== null ||
    addProjectOpen ||
    addEnvOpen ||
    deleteSecret !== null ||
    deleteProject !== null ||
    deleteEnv !== null ||
    shareOpen ||
    importBundleOpen ||
    backupOpen ||
    shareKeyOpen ||
    aboutOpen;
  const anyDialogOpen = modalOpen || paletteOpen;

  // Global keys. Typing contexts and open dialogs swallow single-letter keys.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        // Never open the palette over a modal — it would fight the modal's
        // focus trap (the palette input can't take focus and outside clicks
        // are swallowed). ⌘K still closes an open palette.
        if (modalOpen) return;
        setPaletteOpen((o) => !o);
        return;
      }
      if (anyDialogOpen) return;
      const target = e.target as HTMLElement;
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target.isContentEditable;
      if (typing) return;

      if (e.key === "/" || ((e.metaKey || e.ctrlKey) && e.key === "f")) {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key.toLowerCase() === "n" && project && env) {
        e.preventDefault();
        setSecretDialog({ mode: "new" });
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [anyDialogOpen, modalOpen, project, env]);

  async function lock() {
    const result = await commands.lockVault();
    if (result.status === "ok") markLocked();
  }

  async function confirmDeleteSecret(secret: SecretMeta) {
    const { selectedProjectId, selectedEnvId: envId } = useVault.getState();
    if (!selectedProjectId || !envId) return;
    const result = await commands.removeSecret(selectedProjectId, envId, secret.id);
    if (result.status === "error") {
      push(describeError(result.error));
      return;
    }
    await Promise.all([loadSecrets(), loadProjects()]);
  }

  async function confirmDeleteProject(p: ProjectSummary) {
    const result = await commands.removeProject(p.id);
    if (result.status === "error") {
      push(describeError(result.error));
      return;
    }
    await loadProjects();
  }

  async function confirmDeleteEnv(e: EnvironmentSummary) {
    if (!project) return;
    const result = await commands.removeEnvironment(project.id, e.id);
    if (result.status === "error") {
      push(describeError(result.error));
      return;
    }
    await loadProjects();
  }

  return (
    <>
      <header className="titlebar" data-tauri-drag-region>
        <div className="flex items-center gap-3">
          <span className="text-[13px] font-semibold tracking-[-0.01em]">EnvVault</span>
          <span className="status-pill">
            <span className="status-dot" style={{ background: "var(--ok)" }} />
            Unlocked
          </span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="text-[11.5px] text-[var(--text-faint)]">
            {autoLockMinutes !== null
              ? `Auto-locks after ${autoLockMinutes} min idle`
              : "Auto-lock is off"}
          </span>
          <button
            className="status-pill"
            title={
              guardEnabled
                ? "The Guard is watching your projects for leaked secrets. Click to turn off."
                : "The Guard is off. Click to turn on."
            }
            onClick={() => void toggleGuard()}
            style={guardEnabled ? undefined : { opacity: 0.6 }}
          >
            {guardEnabled ? (
              <Shield size={12} color="var(--ok)" />
            ) : (
              <ShieldOff size={12} color="var(--text-faint)" />
            )}
            Guard {guardEnabled ? "on" : "off"}
          </button>
          <Button
            variant="ghost"
            onClick={() => setView((v) => (v === "health" ? "secrets" : "health"))}
            style={
              view === "health"
                ? { background: "var(--panel-strong)", borderColor: "var(--hairline-strong)" }
                : undefined
            }
          >
            <Activity size={14} />
            Health
          </Button>
          <Button variant="ghost" onClick={() => setPaletteOpen(true)}>
            Commands
            <kbd>⌘K</kbd>
          </Button>
          <Button variant="ghost" onClick={() => void lock()}>
            <LockOpen size={14} />
            Lock
            <kbd>⌘L</kbd>
          </Button>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <Sidebar
          onAddProject={() => setAddProjectOpen(true)}
          onDeleteProject={setDeleteProject}
        />

        <main className="flex min-w-0 flex-1 flex-col overflow-y-auto px-6 py-4">
          {viaRecovery && <RekeyBanner onDone={() => void refresh()} />}

          {guardFinding && (
            <GuardBanner
              finding={guardFinding}
              onSecure={
                guardFinding.kind === "env-appeared"
                  ? () => {
                      // Jump to the flagged project, then open Import & Secure
                      // directly on the file the Guard named.
                      if (guardFinding.projectId !== project?.id) {
                        selectProject(guardFinding.projectId);
                      }
                      setImportFiles([
                        { path: guardFinding.path, fileName: guardFinding.fileName },
                      ]);
                      setGuardFinding(null);
                    }
                  : null
              }
              onDismiss={() => setGuardFinding(null)}
            />
          )}

          {view === "health" ? (
            <HealthDashboard />
          ) : !project ? (
            <EmptyVault onAddProject={() => setAddProjectOpen(true)} />
          ) : (
            <>
              <div className="flex items-center justify-between gap-3">
                <EnvTabs onAddEnv={() => setAddEnvOpen(true)} onRemoveEnv={setDeleteEnv} />
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search
                      size={13}
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-faint)]"
                    />
                    <TextField
                      ref={searchRef}
                      placeholder="Search  /"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Escape") {
                          setFilter("");
                          (e.target as HTMLInputElement).blur();
                        }
                      }}
                      className="w-[180px] pl-8"
                      style={{ height: 30 }}
                    />
                  </div>
                  <Button
                    variant="ghost"
                    title={
                      (env?.secretCount ?? 0) > 0
                        ? `Share ${env?.name ?? "this environment"} as an encrypted bundle`
                        : "Nothing to share — this environment has no secrets"
                    }
                    disabled={(env?.secretCount ?? 0) === 0}
                    onClick={() => setShareOpen(true)}
                  >
                    <Share2 size={14} />
                    Share
                  </Button>
                  <Button onClick={() => setSecretDialog({ mode: "new" })}>
                    <Plus size={14} />
                    New secret
                    <kbd style={{ background: "rgba(0,0,0,0.18)", borderColor: "transparent", color: "inherit" }}>
                      N
                    </kbd>
                  </Button>
                </div>
              </div>

              {envFiles.length > 0 && (
                <div className="rise-in mt-3 flex items-center gap-2.5 rounded-[9px] border border-[rgba(255,190,76,0.35)] bg-[rgba(255,190,76,0.08)] px-3 py-2">
                  <FileWarning size={15} color="var(--warn)" className="flex-none" />
                  <span className="min-w-0 flex-1 truncate text-[12px] text-[var(--text-dim)]">
                    <span className="mono text-[var(--warn)]">
                      {envFiles.map((f) => f.fileName).join(", ")}
                    </span>{" "}
                    — plaintext secrets sitting in this project folder.
                  </span>
                  <Button
                    variant="ghost"
                    style={{ height: 26, borderColor: "rgba(255,190,76,0.4)" }}
                    onClick={() => setImportFiles(envFiles)}
                  >
                    Import &amp; Secure
                  </Button>
                </div>
              )}

              {env?.isProduction && (
                <div className="prod-banner mt-3">
                  <span className="status-dot" style={{ background: "var(--danger)" }} />
                  Production environment — reveals need confirmation. Never use these values in dev.
                </div>
              )}

              <div className="mt-3">
                <SecretsTable
                  filter={filter}
                  isProduction={env?.isProduction ?? false}
                  onEdit={(secret) => setSecretDialog({ mode: "edit", secret })}
                  onDelete={setDeleteSecret}
                />
              </div>
            </>
          )}

          <div className="mt-auto pt-6 text-center">
            <span className="text-[10.5px] text-[var(--text-faint)]">v{appVersion}</span>
          </div>
        </main>
      </div>

      <SecretDialog state={secretDialog} onClose={() => setSecretDialog(null)} />
      <ImportDialog
        files={importFiles}
        onClose={(didImport) => {
          setImportFiles(null);
          if (didImport) {
            void rescanEnvFiles(project?.id);
            void loadSecrets();
            void loadProjects();
          }
        }}
      />
      <AddProjectDialog open={addProjectOpen} onClose={() => setAddProjectOpen(false)} />
      <AddEnvDialog open={addEnvOpen} onClose={() => setAddEnvOpen(false)} />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onLock={() => void lock()}
        onNewSecret={() => setSecretDialog({ mode: "new" })}
        onAddProject={() => setAddProjectOpen(true)}
        onAddEnv={() => setAddEnvOpen(true)}
        onShowHealth={() => setView("health")}
        onShareEnv={env && (env.secretCount ?? 0) > 0 ? () => setShareOpen(true) : null}
        onImportBundle={() => setImportBundleOpen(true)}
        onVaultBackup={() => setBackupOpen(true)}
        onShareKey={() => setShareKeyOpen(true)}
        onAbout={() => setAboutOpen(true)}
      />

      <ShareDialog open={shareOpen} onClose={() => setShareOpen(false)} />
      <ImportBundleDialog open={importBundleOpen} onClose={() => setImportBundleOpen(false)} />
      <VaultBackupDialog open={backupOpen} onClose={() => setBackupOpen(false)} />
      <ShareKeyDialog open={shareKeyOpen} onClose={() => setShareKeyOpen(false)} />
      <AboutDialog open={aboutOpen} onClose={() => setAboutOpen(false)} />

      <ConfirmDialog
        open={deleteSecret !== null}
        onOpenChange={(o) => {
          if (!o) setDeleteSecret(null);
        }}
        title={`Delete ${deleteSecret?.key ?? ""}?`}
        body="The value is removed from the vault on the next save. This cannot be undone (backups keep the last 3 vault versions)."
        confirmLabel="Delete secret"
        danger
        onConfirm={() => {
          if (deleteSecret) void confirmDeleteSecret(deleteSecret);
        }}
      />
      <ConfirmDialog
        open={deleteProject !== null}
        onOpenChange={(o) => {
          if (!o) setDeleteProject(null);
        }}
        title={`Delete project ${deleteProject?.name ?? ""}?`}
        body="Every environment and secret in this project is deleted from the vault. The project folder on disk is not touched."
        confirmLabel="Delete project"
        danger
        onConfirm={() => {
          if (deleteProject) void confirmDeleteProject(deleteProject);
        }}
      />
      <ConfirmDialog
        open={deleteEnv !== null}
        onOpenChange={(o) => {
          if (!o) setDeleteEnv(null);
        }}
        title={`Delete environment ${deleteEnv?.name ?? ""}?`}
        body={`${deleteEnv?.secretCount ?? 0} secret(s) in it will be deleted with it.`}
        confirmLabel="Delete environment"
        danger
        onConfirm={() => {
          if (deleteEnv) void confirmDeleteEnv(deleteEnv);
        }}
      />

      <Toasts />
    </>
  );
}

function EmptyVault({ onAddProject }: { onAddProject: () => void }) {
  return (
    <div className="rise-in mt-16 flex flex-col items-center self-center rounded-2xl border border-dashed border-[var(--hairline-strong)] p-10 text-center">
      <h2 className="text-[16px] font-semibold tracking-[-0.01em]">Add your first project</h2>
      <p className="mt-1.5 max-w-[380px] leading-relaxed text-[var(--text-dim)]">
        Pick a project folder and EnvVault becomes the home for its secrets —
        encrypted here, injected into your dev process, never sitting in the
        repo.
      </p>
      <Button className="mt-5" onClick={onAddProject} autoFocus>
        <Plus size={14} />
        Add project
      </Button>
    </div>
  );
}

/** Forced follow-up after a recovery-key unlock: set a new master password. */
function RekeyBanner({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [strength, setStrength] = useState<Strength | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadScorer();
  }, []);

  const ok = strength !== null && strength.score >= REQUIRED_SCORE;

  async function submit() {
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.rekey(password);
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    setPassword("");
    onDone();
  }

  return (
    <div className="rise-in mb-4 w-full max-w-[560px] self-center rounded-2xl border border-[rgba(255,190,76,0.35)] bg-[rgba(255,190,76,0.08)] p-5">
      <div className="flex items-center gap-2.5">
        <KeyRound size={16} color="var(--warn)" />
        <h2 className="text-[13.5px] font-semibold">You unlocked with your recovery key</h2>
      </div>
      <p className="mt-1.5 leading-relaxed text-[var(--text-dim)]">
        Set a new master password now. Your recovery key stays valid.
      </p>
      <form
        className="mt-4 space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <TextField
          type="password"
          placeholder="New master password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setStrength(e.target.value ? scorePassword(e.target.value) : null);
          }}
        />
        <StrengthMeter strength={strength} />
        {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
        <Button type="submit" className="w-full" disabled={!ok || busy}>
          {busy ? "Saving…" : "Set new master password"}
        </Button>
      </form>
    </div>
  );
}
