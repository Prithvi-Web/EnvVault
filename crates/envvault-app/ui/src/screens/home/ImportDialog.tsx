// Import & Secure (spec F4): preview exactly what will happen, then one
// confirmation does it all — import encrypted, write .env.example, fix
// .gitignore, shred the original (7-day backup). If the file was ever
// committed, the user gets the honest bad news with concrete rotation steps.

import { useEffect, useRef, useState } from "react";
import { Check, ShieldAlert, TriangleAlert } from "lucide-react";
import {
  commands,
  type EnvFileCandidate,
  type ImportPreview,
  type ImportResult,
} from "../../bindings";
import { useVault, useSelectedProject } from "../../store";
import { describeError } from "../../lib/errors";
import { Button } from "../../ui/components";
import { Modal } from "../../ui/dialog";

interface ImportDialogProps {
  files: EnvFileCandidate[] | null;
  onClose: (didImport: boolean) => void;
}

export function ImportDialog({ files, onClose }: ImportDialogProps) {
  const project = useSelectedProject();
  const envId = useVault((s) => s.selectedEnvId);
  const env = project?.environments.find((e) => e.id === envId) ?? null;

  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const doneRef = useRef<HTMLButtonElement>(null);

  const open = files !== null;

  // Keyboard flow: the moment the preview (or the result) is ready, focus
  // the primary action so Enter continues the flow.
  useEffect(() => {
    if (result) doneRef.current?.focus();
    else if (preview) confirmRef.current?.focus();
  }, [preview === null, result === null]);

  useEffect(() => {
    setPreview(null);
    setResult(null);
    setError(null);
    setBusy(false);
    setSelectedPath(files?.length === 1 ? (files[0]?.path ?? null) : null);
  }, [files]);

  // Load the preview whenever a file is chosen.
  useEffect(() => {
    if (!open || !selectedPath || !project || !envId || result) return;
    void (async () => {
      const r = await commands.previewEnvImport(project.id, envId, selectedPath);
      if (r.status === "ok") setPreview(r.data);
      else setError(describeError(r.error));
    })();
  }, [open, selectedPath, project?.id, envId, result]);

  async function runImport() {
    if (!project || !envId || !selectedPath || busy) return;
    setBusy(true);
    setError(null);
    const r = await commands.importEnv(project.id, envId, selectedPath);
    setBusy(false);
    if (r.status === "ok") setResult(r.data);
    else setError(describeError(r.error));
  }

  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose(result !== null);
      }}
      title={result ? "Secured" : "Import & Secure"}
      description={
        result
          ? undefined
          : env
            ? `Into ${project?.name ?? ""} → ${env.name}${env.isProduction ? " (production)" : ""}`
            : undefined
      }
    >
      {/* Step 1: choose a file (only when several were found) */}
      {!result && !selectedPath && files && files.length > 1 && (
        <div className="space-y-2">
          <p className="text-[12.5px] text-[var(--text-dim)]">
            Several plaintext env files were found. Pick one to secure:
          </p>
          {files.map((f) => (
            <button
              key={f.path}
              className="sidebar-item mono"
              onClick={() => setSelectedPath(f.path)}
            >
              {f.fileName}
            </button>
          ))}
        </div>
      )}

      {/* Step 2: preview */}
      {!result && selectedPath && (
        <div className="space-y-3.5">
          {preview?.exposure && (
            <div className="rounded-[10px] border border-[rgba(255,92,87,0.35)] bg-[var(--danger-soft)] p-3.5">
              <div className="flex items-center gap-2 font-semibold text-[var(--danger)]">
                <ShieldAlert size={15} />
                This file is in your git history
              </div>
              <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--text-dim)]">
                <span className="mono">{preview.fileName}</span> was committed in{" "}
                <b>{preview.exposure.commitCount}</b>{" "}
                {preview.exposure.commitCount === 1 ? "commit" : "commits"}
                {preview.exposure.lastCommit
                  ? `, most recently ${new Date(preview.exposure.lastCommit).toLocaleDateString()}`
                  : ""}
                . Those values are already exposed — removing the file now does{" "}
                <b>not</b> remove them from history. They must be rotated;
                you'll get exact steps after the import.
              </p>
            </div>
          )}

          {preview === null && !error && (
            <p className="text-[12.5px] text-[var(--text-faint)]">Reading file…</p>
          )}

          {preview && (
            <>
              <div className="max-h-[240px] overflow-y-auto rounded-[10px] border border-[var(--hairline)]">
                {preview.entries.map((e) => (
                  <div
                    key={e.key}
                    className="flex items-center gap-2 border-b border-[var(--hairline)] px-3 py-2 last:border-b-0"
                  >
                    <span className="mono min-w-0 flex-1 truncate text-[12px] font-medium">
                      {e.key}
                    </span>
                    {e.detectedLabel && <span className="badge">{e.detectedLabel}</span>}
                    {e.willUpdate && <span className="badge">updates existing</span>}
                    {e.hadDuplicates && <span className="badge">deduplicated</span>}
                    <span className="masked-dots mono text-[11px]">
                      {"•".repeat(Math.min(Math.max(e.valueLength, 4), 14))}
                    </span>
                  </div>
                ))}
                {preview.entries.length === 0 && (
                  <p className="px-3 py-4 text-center text-[12px] text-[var(--text-faint)]">
                    No usable entries found in this file.
                  </p>
                )}
              </div>

              {preview.warnings.length > 0 && (
                <div className="text-[11.5px] text-[var(--warn)]">
                  {preview.warnings.map((w) => (
                    <div key={w} className="flex items-start gap-1.5">
                      <TriangleAlert size={12} className="mt-0.5 flex-none" />
                      {w}
                    </div>
                  ))}
                </div>
              )}

              <p className="text-[11.5px] leading-relaxed text-[var(--text-faint)]">
                Importing will also write{" "}
                <span className="mono">{preview.fileName}.example</span> (keys only,
                safe to commit), add the file to <span className="mono">.gitignore</span>,
                and shred the original — a backup is kept outside the repo for 7 days.
              </p>
            </>
          )}

          {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}

          <div className="flex justify-end gap-2.5">
            <Button variant="ghost" onClick={() => onClose(false)} disabled={busy}>
              Cancel
            </Button>
            <Button
              ref={confirmRef}
              onClick={() => void runImport()}
              // Not `disabled` while busy: disabling the focused button mid-
              // import throws focus out of the dialog and Radix dismisses it.
              // runImport itself guards re-entry.
              disabled={!preview || preview.entries.length === 0}
              aria-busy={busy}
            >
              {busy ? "Securing…" : "Import & Secure"}
            </Button>
          </div>
        </div>
      )}

      {/* Step 3: result */}
      {result && (
        <div className="space-y-3.5">
          <ul className="space-y-1.5 text-[12.5px] text-[var(--text-dim)]">
            <Done>
              {result.imported.length} imported
              {result.updated.length > 0 ? `, ${result.updated.length} updated` : ""} — encrypted
              in your vault
            </Done>
            {result.examplePath && (
              <Done>
                Wrote <span className="mono">{fileTail(result.examplePath)}</span> (safe to
                commit)
              </Done>
            )}
            {result.gitignoreUpdated ? (
              <Done>
                Added to <span className="mono">.gitignore</span>
              </Done>
            ) : (
              <Done>
                <span className="mono">.gitignore</span> already covered it
              </Done>
            )}
            {result.backupPath && (
              <Done>
                Original shredded — recovery copy kept for 7 days outside the repo
              </Done>
            )}
          </ul>

          {result.exposure && (
            <div className="rounded-[10px] border border-[rgba(255,92,87,0.35)] bg-[var(--danger-soft)] p-3.5">
              <div className="flex items-center gap-2 font-semibold text-[var(--danger)]">
                <ShieldAlert size={15} />
                Rotate these now
              </div>
              <p className="mt-1 text-[11.5px] leading-relaxed text-[var(--text-dim)]">
                The old values live in {result.exposure.commitCount}{" "}
                {result.exposure.commitCount === 1 ? "commit" : "commits"} forever. Rotating
                makes them worthless.
              </p>
              <div className="mt-2.5 space-y-2.5">
                {result.rotationAdvice.map((a) => (
                  <div key={a.label} className="text-[11.5px] leading-relaxed">
                    <div className="font-semibold text-[var(--text)]">
                      {a.label}{" "}
                      <span className="mono font-normal text-[var(--text-faint)]">
                        ({a.keys.join(", ")})
                      </span>
                    </div>
                    <div className="text-[var(--text-dim)]">{a.steps}</div>
                    {a.url && (
                      <div className="mono select-text text-[var(--accent)]">{a.url}</div>
                    )}
                  </div>
                ))}
                {result.rotationAdvice.length === 0 && (
                  <p className="text-[11.5px] text-[var(--text-dim)]">
                    Rotate every imported credential at its provider.
                  </p>
                )}
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <Button ref={doneRef} onClick={() => onClose(true)}>
              Done
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function Done({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2">
      <Check size={14} color="var(--ok)" strokeWidth={2.4} className="mt-0.5 flex-none" />
      <span>{children}</span>
    </li>
  );
}

function fileTail(path: string): string {
  return path.split(/[/\\]/).filter(Boolean).pop() ?? path;
}
