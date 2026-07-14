// Import a share bundle (spec F8, recipient side). The bundle is decrypted
// in Rust and held there as the pending import — only metadata reaches this
// component. Confirm applies it; cancel/close drops it (zeroized).

import { useEffect, useMemo, useState } from "react";
import { open as openFile } from "@tauri-apps/plugin-dialog";
import { FileKey2, FolderOpen } from "lucide-react";
import { commands, type SharePreview, type ShareBundleKind } from "../../bindings";
import { useVault } from "../../store";
import { describeError, formatDate } from "../../lib/errors";
import { Button, TextField } from "../../ui/components";
import { Modal } from "../../ui/dialog";
import { useToasts } from "../../ui/toast";

interface ImportBundleDialogProps {
  open: boolean;
  onClose: () => void;
}

const NEW_ENV = "__create_new__";

export function ImportBundleDialog({ open: isOpen, onClose }: ImportBundleDialogProps) {
  const projects = useVault((s) => s.projects);
  const selectedProjectId = useVault((s) => s.selectedProjectId);
  const loadProjects = useVault((s) => s.loadProjects);
  const loadSecrets = useVault((s) => s.loadSecrets);
  const push = useToasts((s) => s.push);

  const [path, setPath] = useState("");
  const [kind, setKind] = useState<ShareBundleKind | null>(null);
  const [credential, setCredential] = useState("");
  const [preview, setPreview] = useState<SharePreview | null>(null);
  const [targetProjectId, setTargetProjectId] = useState("");
  const [targetEnv, setTargetEnv] = useState(NEW_ENV);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setPath("");
      setKind(null);
      setCredential("");
      setPreview(null);
      setTargetProjectId("");
      setTargetEnv(NEW_ENV);
      setBusy(false);
      setError(null);
    }
  }, [isOpen]);

  const targetProject = projects.find((p) => p.id === targetProjectId) ?? null;
  const envMatch = useMemo(() => {
    if (!preview || !targetProject) return null;
    return (
      targetProject.environments.find(
        (e) => e.name.toLowerCase() === preview.environmentName.toLowerCase(),
      ) ?? null
    );
  }, [preview, targetProject]);

  function close(didImport: boolean) {
    if (preview && !didImport) void commands.cancelShareImport();
    onClose();
  }

  async function pickFile() {
    const selection = await openFile({
      title: "Choose a share bundle",
      multiple: false,
      filters: [{ name: "age encrypted file", extensions: ["age"] }],
    });
    if (typeof selection !== "string") return;
    setError(null);
    setKind(null);
    setPath(selection);
    const result = await commands.inspectShareBundle(selection);
    if (result.status === "error") {
      setError(describeError(result.error));
      setPath("");
      return;
    }
    setKind(result.data);
    setCredential("");
  }

  async function decrypt() {
    if (!path || !kind || !credential || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.previewShareImport(
      path,
      kind === "passphrase" ? credential : null,
      kind === "recipientKeys" ? credential : null,
    );
    setBusy(false);
    setCredential("");
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    const p = result.data;
    setPreview(p);
    // Default target: the project whose name matches the bundle, else the
    // one currently selected, else the first.
    const byName = projects.find(
      (proj) => proj.name.toLowerCase() === p.projectName.toLowerCase(),
    );
    const target = byName ?? projects.find((proj) => proj.id === selectedProjectId) ?? projects[0];
    if (target) {
      setTargetProjectId(target.id);
      const match = target.environments.find(
        (e) => e.name.toLowerCase() === p.environmentName.toLowerCase(),
      );
      setTargetEnv(match ? match.id : NEW_ENV);
    }
  }

  async function confirmImport() {
    if (!preview || !targetProject || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.confirmShareImport(
      targetProject.id,
      targetEnv === NEW_ENV ? null : targetEnv,
      targetEnv === NEW_ENV ? preview.environmentName : null,
    );
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    const r = result.data;
    const parts = [
      `${r.added.length} added`,
      `${r.updated.length} updated`,
      ...(r.unchangedCount > 0 ? [`${r.unchangedCount} unchanged`] : []),
    ];
    push(`Imported into ${r.projectName} [${r.environmentName}] — ${parts.join(", ")}`);
    await Promise.all([loadProjects(), loadSecrets()]);
    close(true);
  }

  const targetEnvIsProduction =
    targetEnv !== NEW_ENV &&
    (targetProject?.environments.find((e) => e.id === targetEnv)?.isProduction ?? false);

  return (
    <Modal
      open={isOpen}
      onOpenChange={(o) => {
        if (!o) close(false);
      }}
      title="Import a share bundle"
      description={
        preview
          ? undefined
          : "Open an encrypted bundle a teammate sent you. Nothing is added to your vault until you confirm."
      }
    >
      {!preview ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void decrypt();
          }}
        >
          <div>
            <label className="eyebrow mb-1.5 block">Bundle file</label>
            <div className="flex gap-2">
              <TextField
                readOnly
                placeholder="No file chosen"
                value={path}
                className="mono flex-1 text-[11.5px]"
                tabIndex={-1}
              />
              <Button type="button" variant="ghost" onClick={() => void pickFile()}>
                <FolderOpen size={14} />
                Choose…
              </Button>
            </div>
          </div>

          {kind && (
            <div>
              <label className="eyebrow mb-1.5 block" htmlFor="bundle-credential">
                {kind === "passphrase" ? "Bundle passphrase" : "Your master password"}
              </label>
              <TextField
                id="bundle-credential"
                type="password"
                autoFocus
                placeholder={
                  kind === "passphrase"
                    ? "The passphrase the sender gave you"
                    : "This bundle was encrypted to your share key"
                }
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
              />
            </div>
          )}

          {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
          <div className="flex justify-end gap-2.5 pt-1">
            <Button type="button" variant="ghost" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!path || !kind || !credential || busy}>
              {busy ? "Decrypting…" : "Decrypt & preview"}
            </Button>
          </div>
        </form>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-2.5 rounded-[9px] border border-[var(--hairline)] bg-[var(--panel)] px-3 py-2.5">
            <FileKey2 size={15} className="flex-none text-[var(--text-dim)]" />
            <div className="min-w-0 flex-1 text-[12.5px] leading-snug">
              <span className="font-medium">{preview.projectName}</span>{" "}
              <span
                className="mono text-[11px]"
                style={{ color: preview.isProduction ? "var(--danger)" : "var(--text-dim)" }}
              >
                [{preview.environmentName}]
              </span>
              <div className="text-[11px] text-[var(--text-faint)]">
                {preview.entries.length} secret{preview.entries.length === 1 ? "" : "s"} · created{" "}
                {formatDate(preview.createdAt)}
                {preview.expiresAt ? ` · valid until ${formatDate(preview.expiresAt)}` : ""}
              </div>
            </div>
          </div>

          <div className="max-h-[180px] overflow-y-auto rounded-[9px] border border-[var(--hairline)]">
            {preview.entries.map((entry) => (
              <div
                key={entry.key}
                className="flex items-center gap-2 border-b border-[var(--hairline)] px-3 py-1.5 text-[12px] last:border-b-0"
              >
                <span className="mono min-w-0 flex-1 truncate">{entry.key}</span>
                {entry.detectedLabel && (
                  <span className="text-[10.5px] text-[var(--text-faint)]">
                    {entry.detectedLabel}
                  </span>
                )}
                <span className="mono text-[10.5px] text-[var(--text-faint)]">
                  {"•".repeat(Math.min(8, Math.max(3, Math.floor(entry.valueLength / 6))))}
                </span>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="eyebrow mb-1.5 block" htmlFor="import-project">
                Into project
              </label>
              <select
                id="import-project"
                className="field w-full"
                value={targetProjectId}
                onChange={(e) => {
                  setTargetProjectId(e.target.value);
                  const proj = projects.find((p) => p.id === e.target.value);
                  const match = proj?.environments.find(
                    (env) => env.name.toLowerCase() === preview.environmentName.toLowerCase(),
                  );
                  setTargetEnv(match ? match.id : NEW_ENV);
                }}
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="eyebrow mb-1.5 block" htmlFor="import-env">
                Environment
              </label>
              <select
                id="import-env"
                className="field w-full"
                value={targetEnv}
                onChange={(e) => setTargetEnv(e.target.value)}
              >
                {targetProject?.environments.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name}
                    {e.isProduction ? " (production)" : ""}
                  </option>
                ))}
                {!envMatch && (
                  <option value={NEW_ENV}>Create “{preview.environmentName}”</option>
                )}
              </select>
            </div>
          </div>

          {projects.length === 0 && (
            <p className="text-[12.5px] text-[var(--danger)]">
              Bundles import into a project — add one first (⌘K → “Add project”), then
              come back. The decrypted bundle is dropped when you close this dialog.
            </p>
          )}

          {targetEnvIsProduction && (
            <div className="prod-banner">
              <span className="status-dot" style={{ background: "var(--danger)" }} />
              These secrets will land in production.
            </div>
          )}

          <p className="text-[11.5px] leading-relaxed text-[var(--text-faint)]">
            Keys you already have are updated when the value differs; identical values
            are left untouched.
          </p>

          {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
          <div className="flex justify-end gap-2.5 pt-1">
            <Button type="button" variant="ghost" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => void confirmImport()}
              disabled={busy || !targetProject || projects.length === 0}
            >
              {busy ? "Importing…" : `Import ${preview.entries.length} secret${preview.entries.length === 1 ? "" : "s"}`}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}
