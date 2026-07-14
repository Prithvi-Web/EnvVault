// Secure Share (spec F8): export the selected environment as an encrypted
// age file. Protected by a passphrase (communicated out-of-band) or by the
// recipients' public keys. No server, no upload — the file travels however
// the user wants.

import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Check, Copy, RefreshCw } from "lucide-react";
import { commands } from "../../bindings";
import { useVault, useSelectedProject } from "../../store";
import { describeError } from "../../lib/errors";
import {
  DEFAULT_EXPIRY_HOURS,
  EXPIRY_OPTIONS,
  generateSharePassphrase,
  MIN_SHARE_PASSPHRASE_CHARS,
} from "../../lib/share";
import { Button, TextField } from "../../ui/components";
import { Modal } from "../../ui/dialog";

interface ShareDialogProps {
  open: boolean;
  onClose: () => void;
}

type Method = "passphrase" | "keys";

export function ShareDialog({ open: isOpen, onClose }: ShareDialogProps) {
  const project = useSelectedProject();
  const selectedEnvId = useVault((s) => s.selectedEnvId);
  const env = project?.environments.find((e) => e.id === selectedEnvId) ?? null;

  const [method, setMethod] = useState<Method>("passphrase");
  const [passphrase, setPassphrase] = useState("");
  const [keys, setKeys] = useState("");
  const [expiryHours, setExpiryHours] = useState<number | null>(DEFAULT_EXPIRY_HOURS);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [savedTo, setSavedTo] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setMethod("passphrase");
      setPassphrase(generateSharePassphrase());
      setKeys("");
      setExpiryHours(DEFAULT_EXPIRY_HOURS);
      setBusy(false);
      setError(null);
      setCopied(false);
      setSavedTo(null);
    }
  }, [isOpen]);

  if (!project || !env) return null;

  const passphraseTooShort =
    method === "passphrase" && passphrase.length < MIN_SHARE_PASSPHRASE_CHARS;
  const noKeys = method === "keys" && keys.trim().length === 0;
  const disabled = busy || passphraseTooShort || noKeys;

  async function copyPassphrase() {
    await writeText(passphrase);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  async function exportBundle() {
    if (disabled || !project || !env) return;
    setError(null);

    let destPath: string | null;
    try {
      destPath = await save({
        title: "Save share bundle",
        // A neutral default name on purpose: the filename travels in the
        // clear, so it should not announce what is inside.
        defaultPath: "envvault-share.age",
        filters: [{ name: "age encrypted file", extensions: ["age"] }],
      });
    } catch (e) {
      setError(`Could not open the save dialog: ${String(e)}`);
      return;
    }
    if (typeof destPath !== "string") return;

    setBusy(true);
    const result = await commands.exportShareBundle(
      project.id,
      env.id,
      method === "passphrase" ? passphrase : null,
      method === "keys"
        ? keys
            .split("\n")
            .map((k) => k.trim())
            .filter(Boolean)
        : [],
      expiryHours,
      destPath,
    );
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    setSavedTo(destPath);
  }

  return (
    <Modal
      open={isOpen}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={`Share ${project.name} [${env.name}]`}
      description={
        savedTo
          ? undefined
          : `Exports the ${env.secretCount} secret${env.secretCount === 1 ? "" : "s"} of this environment as one encrypted file. Send it over Signal, AirDrop, a USB stick — it never touches a server.`
      }
      danger={env.isProduction && !savedTo}
    >
      {savedTo ? (
        <div className="space-y-3">
          <p className="text-[12.5px] leading-relaxed text-[var(--text-dim)]">
            Encrypted bundle written to{" "}
            <span className="mono text-[11.5px] text-[var(--text)]">{savedTo}</span>
          </p>
          {method === "passphrase" && (
            <div className="rounded-[9px] border border-[rgba(255,190,76,0.35)] bg-[rgba(255,190,76,0.08)] px-3 py-2.5 text-[12.5px] leading-relaxed text-[var(--text-dim)]">
              Share the passphrase over a <strong>different channel</strong> than the
              file — if both travel together, the encryption bought nothing.
              <div className="mt-2 flex items-center gap-2">
                <span className="mono flex-1 text-[12px] text-[var(--text)]">{passphrase}</span>
                <Button variant="ghost" style={{ height: 26 }} onClick={() => void copyPassphrase()}>
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
            </div>
          )}
          <p className="text-[12px] leading-relaxed text-[var(--text-faint)]">
            The recipient imports it with EnvVault (⌘K → “Import share bundle”, or{" "}
            <span className="mono">envvault import</span>) — or decrypts it with the
            standard <span className="mono">age</span> CLI. Expiry is checked on import;
            it is a courtesy guardrail, not a cryptographic guarantee.
          </p>
          <div className="flex justify-end pt-1">
            <Button onClick={onClose}>Done</Button>
          </div>
        </div>
      ) : (
        <form
          className="space-y-3.5"
          onSubmit={(e) => {
            e.preventDefault();
            void exportBundle();
          }}
        >
          {env.isProduction && (
            <div className="prod-banner">
              <span className="status-dot" style={{ background: "var(--danger)" }} />
              You are sharing production secrets.
            </div>
          )}

          <div>
            <label className="eyebrow mb-1.5 block">Protect it with</label>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="ghost"
                className="flex-1"
                style={
                  method === "passphrase"
                    ? { background: "var(--panel-strong)", borderColor: "var(--hairline-strong)" }
                    : undefined
                }
                onClick={() => setMethod("passphrase")}
              >
                A passphrase
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="flex-1"
                style={
                  method === "keys"
                    ? { background: "var(--panel-strong)", borderColor: "var(--hairline-strong)" }
                    : undefined
                }
                onClick={() => setMethod("keys")}
              >
                Recipient keys
              </Button>
            </div>
          </div>

          {method === "passphrase" ? (
            <div>
              <div className="flex gap-2">
                <TextField
                  className="mono flex-1 text-[12px]"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  hasError={passphraseTooShort && passphrase.length > 0}
                />
                <Button
                  type="button"
                  variant="ghost"
                  title="Generate a new passphrase"
                  onClick={() => setPassphrase(generateSharePassphrase())}
                >
                  <RefreshCw size={13} />
                </Button>
                <Button type="button" variant="ghost" onClick={() => void copyPassphrase()}>
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                </Button>
              </div>
              <p className="mt-1.5 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
                {passphraseTooShort && passphrase.length > 0
                  ? `At least ${MIN_SHARE_PASSPHRASE_CHARS} characters.`
                  : "Tell it to the recipient out-of-band — never in the same channel as the file."}
              </p>
            </div>
          ) : (
            <div>
              <textarea
                className="field min-h-[72px] w-full resize-y py-2 leading-relaxed"
                style={{ height: "auto", fontFamily: "var(--font-mono, monospace)", fontSize: 11.5 }}
                placeholder={"age1… or ssh-ed25519 AAAA… — one key per line"}
                value={keys}
                onChange={(e) => setKeys(e.target.value)}
                spellCheck={false}
              />
              <p className="mt-1.5 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
                Ask each recipient for their EnvVault share key (⌘K → “My share key”) or
                use their SSH public key. Only those keys can open the bundle — no
                passphrase to pass around.
              </p>
            </div>
          )}

          <div>
            <label className="eyebrow mb-1.5 block" htmlFor="share-expiry">
              Import deadline
            </label>
            <select
              id="share-expiry"
              className="field w-full"
              value={expiryHours === null ? "never" : String(expiryHours)}
              onChange={(e) =>
                setExpiryHours(e.target.value === "never" ? null : Number(e.target.value))
              }
            >
              {EXPIRY_OPTIONS.map((o) => (
                <option key={o.label} value={o.hours === null ? "never" : String(o.hours)}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
          <div className="flex justify-end gap-2.5 pt-1">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={disabled}>
              {busy ? "Encrypting…" : "Choose where to save…"}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}
