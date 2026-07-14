// Vault backup & portability (spec F9). Export writes a copy of the already-
// encrypted vault file — safe for Dropbox, USB, anywhere. Import merges
// another EnvVault file into this one, or replaces this vault entirely.

import { useEffect, useState } from "react";
import { open as openFile, save } from "@tauri-apps/plugin-dialog";
import { FolderOpen, HardDriveDownload, HardDriveUpload } from "lucide-react";
import { commands } from "../../bindings";
import { useVault } from "../../store";
import { describeError } from "../../lib/errors";
import { Button, TextField } from "../../ui/components";
import { ConfirmDialog, Modal } from "../../ui/dialog";
import { useToasts } from "../../ui/toast";

interface VaultBackupDialogProps {
  open: boolean;
  onClose: () => void;
}

type Mode = "merge" | "replace";

export function VaultBackupDialog({ open: isOpen, onClose }: VaultBackupDialogProps) {
  const loadProjects = useVault((s) => s.loadProjects);
  const markLocked = useVault((s) => s.markLocked);
  const push = useToasts((s) => s.push);

  const [importPath, setImportPath] = useState("");
  const [mode, setMode] = useState<Mode>("merge");
  const [password, setPassword] = useState("");
  const [confirmReplace, setConfirmReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setImportPath("");
      setMode("merge");
      setPassword("");
      setConfirmReplace(false);
      setBusy(false);
      setError(null);
    }
  }, [isOpen]);

  async function exportBackup() {
    setError(null);
    // Local date, not toISOString() — UTC can already be tomorrow.
    const now = new Date();
    const date = [
      now.getFullYear(),
      String(now.getMonth() + 1).padStart(2, "0"),
      String(now.getDate()).padStart(2, "0"),
    ].join("-");
    let destPath: string | null;
    try {
      destPath = await save({
        title: "Save encrypted vault backup",
        defaultPath: `envvault-backup-${date}.age`,
        filters: [{ name: "age encrypted file", extensions: ["age"] }],
      });
    } catch (e) {
      setError(`Could not open the save dialog: ${String(e)}`);
      return;
    }
    if (typeof destPath !== "string") return;
    const result = await commands.exportVaultBackup(destPath);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    push("Encrypted backup written — it is ciphertext, safe to store anywhere.");
    onClose();
  }

  async function pickImportFile() {
    const selection = await openFile({
      title: "Choose an EnvVault file",
      multiple: false,
      filters: [{ name: "age encrypted file", extensions: ["age"] }],
    });
    if (typeof selection === "string") {
      setImportPath(selection);
      setError(null);
    }
  }

  async function runMerge() {
    if (!importPath || !password || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.importVaultMerge(importPath, password);
    setBusy(false);
    setPassword("");
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    const r = result.data;
    push(
      `Merged: ${r.projectsAdded} project${r.projectsAdded === 1 ? "" : "s"}, ` +
        `${r.secretsAdded} secret${r.secretsAdded === 1 ? "" : "s"} added, ` +
        `${r.secretsUpdated} updated.`,
    );
    await loadProjects();
    onClose();
  }

  async function runReplace() {
    if (!importPath || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.importVaultReplace(importPath);
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    // The old session is gone by design; the imported vault opens with its
    // own master password.
    markLocked();
  }

  return (
    <>
      <Modal
        open={isOpen}
        onOpenChange={(o) => {
          if (!o) onClose();
        }}
        title="Backup & portability"
        description="Your vault is one encrypted age file. Copy it out, or bring another one in — your data is never hostage."
      >
        <div className="space-y-4">
          <section className="rounded-[9px] border border-[var(--hairline)] bg-[var(--panel)] p-3">
            <div className="flex items-center gap-2">
              <HardDriveDownload size={15} className="text-[var(--text-dim)]" />
              <h3 className="text-[13px] font-semibold">Export a backup</h3>
            </div>
            <p className="mt-1 text-[12px] leading-relaxed text-[var(--text-dim)]">
              Writes a copy of the encrypted vault. It stays ciphertext — putting it in
              Dropbox or on a USB stick is safe.
            </p>
            <div className="mt-2.5 flex justify-end">
              <Button variant="ghost" onClick={() => void exportBackup()}>
                Export encrypted vault…
              </Button>
            </div>
          </section>

          <section className="rounded-[9px] border border-[var(--hairline)] bg-[var(--panel)] p-3">
            <div className="flex items-center gap-2">
              <HardDriveUpload size={15} className="text-[var(--text-dim)]" />
              <h3 className="text-[13px] font-semibold">Import a vault</h3>
            </div>
            <div className="mt-2.5 flex gap-2">
              <TextField
                readOnly
                placeholder="No file chosen"
                value={importPath}
                className="mono flex-1 text-[11.5px]"
                tabIndex={-1}
              />
              <Button type="button" variant="ghost" onClick={() => void pickImportFile()}>
                <FolderOpen size={14} />
                Choose…
              </Button>
            </div>

            {importPath && (
              <div className="mt-3 space-y-3">
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    className="flex-1"
                    style={
                      mode === "merge"
                        ? { background: "var(--panel-strong)", borderColor: "var(--hairline-strong)" }
                        : undefined
                    }
                    onClick={() => setMode("merge")}
                  >
                    Merge into this vault
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    className="flex-1"
                    style={
                      mode === "replace"
                        ? {
                            background: "rgba(255,90,90,0.12)",
                            borderColor: "rgba(255,90,90,0.4)",
                            color: "var(--danger)",
                          }
                        : undefined
                    }
                    onClick={() => setMode("replace")}
                  >
                    Replace this vault
                  </Button>
                </div>

                {mode === "merge" ? (
                  <form
                    className="space-y-2.5"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void runMerge();
                    }}
                  >
                    <p className="text-[11.5px] leading-relaxed text-[var(--text-faint)]">
                      Adds everything from the file that you don't have; where a secret
                      exists in both with different values, the imported file wins. Needs
                      that file's master password.
                    </p>
                    <TextField
                      type="password"
                      placeholder="Master password of the imported file"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <div className="flex justify-end">
                      <Button type="submit" disabled={!password || busy}>
                        {busy ? "Merging…" : "Merge"}
                      </Button>
                    </div>
                  </form>
                ) : (
                  <div className="space-y-2.5">
                    <p className="text-[11.5px] leading-relaxed text-[var(--danger)]">
                      Replaces your entire vault with the file. Afterwards it unlocks with
                      the imported file's master password — not your current one. Your
                      current vault is kept in the rolling backups next to the vault file.
                    </p>
                    <div className="flex justify-end">
                      <Button
                        style={{ background: "var(--danger)", color: "#fff" }}
                        disabled={busy}
                        onClick={() => setConfirmReplace(true)}
                      >
                        Replace vault…
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {error && <p className="mt-2 text-[12.5px] text-[var(--danger)]">{error}</p>}
          </section>

          <div className="flex justify-end">
            <Button variant="ghost" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={confirmReplace}
        onOpenChange={setConfirmReplace}
        title="Replace the entire vault?"
        body="Everything currently in this vault is swapped out for the imported file, and the app locks. You will need the imported file's master password to get back in. The last 3 versions of your current vault remain as backups."
        confirmLabel="Replace vault"
        danger
        onConfirm={() => void runReplace()}
      />
    </>
  );
}
