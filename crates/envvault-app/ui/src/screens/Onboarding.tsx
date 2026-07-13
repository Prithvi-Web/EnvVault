// First run: explain the model, set the master password, acknowledge the
// no-reset reality, save the recovery key. The password and recovery key
// exist only in local state here and are discarded on unmount.

import { useEffect, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { ShieldCheck, Copy, Check } from "lucide-react";
import { commands } from "../bindings";
import { useVault } from "../store";
import { describeError } from "../lib/errors";
import {
  loadScorer,
  scorePassword,
  REQUIRED_SCORE,
  type Strength,
} from "../lib/password";
import { Button, Checkbox, StrengthMeter, TextField } from "../ui/components";

type Step = "intro" | "password" | "warning" | "recovery";

export default function Onboarding() {
  const markUnlocked = useVault((s) => s.markUnlocked);
  const [step, setStep] = useState<Step>("intro");

  // Secrets stay in local state only.
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [strength, setStrength] = useState<Strength | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [wantRecovery, setWantRecovery] = useState(true);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [savedRecovery, setSavedRecovery] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadScorer();
  }, []);

  const passwordOk =
    strength !== null && strength.score >= REQUIRED_SCORE && password === confirm;
  const mismatch = confirm.length > 0 && password !== confirm;

  async function createVault() {
    setBusy(true);
    setError(null);
    const result = await commands.createVault(password, wantRecovery);
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    setPassword("");
    setConfirm("");
    if (result.data.recoveryKey) {
      setRecoveryKey(result.data.recoveryKey);
      setStep("recovery");
    } else {
      markUnlocked(false);
    }
  }

  async function copyRecoveryKey() {
    if (!recoveryKey) return;
    await writeText(recoveryKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="flex flex-1 items-center justify-center p-8" data-tauri-drag-region>
      <div className="glass-card rise-in w-[440px] p-8" key={step}>
        {step === "intro" && (
          <>
            <div className="mb-5 flex h-11 w-11 items-center justify-center rounded-xl border border-[var(--hairline)] bg-[var(--accent-soft)]">
              <ShieldCheck size={22} color="var(--accent)" strokeWidth={1.8} />
            </div>
            <h1 className="text-[21px] font-semibold tracking-[-0.01em]">
              Your secrets live here now
            </h1>
            <p className="mt-2 leading-relaxed text-[var(--text-dim)]">
              EnvVault keeps project secrets in one encrypted vault on this
              computer — not in your repo, not in the cloud. Your dev process
              gets them injected at launch, so a plaintext{" "}
              <span className="mono">.env</span> never has to exist again.
            </p>
            <ul className="mt-4 space-y-2 text-[var(--text-dim)]">
              {[
                "No account. No signup. Works in airplane mode, forever.",
                "Encrypted with age — an audited, open format.",
                "Zero network access. Verifiable, not just promised.",
              ].map((line) => (
                <li key={line} className="flex gap-2.5">
                  <Check size={15} color="var(--ok)" strokeWidth={2.2} className="mt-0.5 flex-none" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
            <Button className="mt-6 w-full" onClick={() => setStep("password")} autoFocus>
              Set up my vault
            </Button>
          </>
        )}

        {step === "password" && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (passwordOk) setStep("warning");
            }}
          >
            <p className="eyebrow">Step 1 of 2</p>
            <h1 className="mt-1.5 text-[21px] font-semibold tracking-[-0.01em]">
              Choose a master password
            </h1>
            <p className="mt-2 leading-relaxed text-[var(--text-dim)]">
              This one password protects everything. Make it long — a few
              random words beat a short jumble.
            </p>
            <div className="mt-5 space-y-3">
              <TextField
                type="password"
                placeholder="Master password"
                value={password}
                autoFocus
                onChange={(e) => {
                  setPassword(e.target.value);
                  setStrength(e.target.value ? scorePassword(e.target.value) : null);
                }}
              />
              <StrengthMeter strength={strength} />
              <TextField
                type="password"
                placeholder="Repeat password"
                value={confirm}
                hasError={mismatch}
                onChange={(e) => setConfirm(e.target.value)}
              />
              {mismatch && (
                <p className="text-[11.5px] text-[var(--danger)]">
                  Passwords don't match yet.
                </p>
              )}
            </div>
            <div className="mt-6 flex gap-2.5">
              <Button type="button" variant="ghost" onClick={() => setStep("intro")}>
                Back
              </Button>
              <Button type="submit" className="flex-1" disabled={!passwordOk}>
                Continue
              </Button>
            </div>
          </form>
        )}

        {step === "warning" && (
          <>
            <p className="eyebrow">Step 2 of 2</p>
            <h1 className="mt-1.5 text-[21px] font-semibold tracking-[-0.01em] text-[var(--danger)]">
              There is no password reset
            </h1>
            <p className="mt-2 leading-relaxed text-[var(--text-dim)]">
              No recovery email. No cloud backup. No support line that can help.
              If you forget this password, your secrets are gone permanently.
              That isn't a limitation — it's the entire point: nobody but you
              can ever open this vault.
            </p>
            <div className="mt-5 space-y-3.5">
              <Checkbox checked={acknowledged} onChange={setAcknowledged}>
                I understand: lose the password, lose the secrets.
              </Checkbox>
              <Checkbox checked={wantRecovery} onChange={setWantRecovery}>
                Generate a recovery key <span className="text-[var(--text-faint)]">(recommended —
                a one-time backup key you store somewhere safe)</span>
              </Checkbox>
            </div>
            {error && <p className="mt-4 text-[12.5px] text-[var(--danger)]">{error}</p>}
            <div className="mt-6 flex gap-2.5">
              <Button variant="ghost" onClick={() => setStep("password")} disabled={busy}>
                Back
              </Button>
              <Button
                className="flex-1"
                disabled={!acknowledged || busy}
                onClick={() => void createVault()}
              >
                {busy ? "Creating vault…" : "Create my vault"}
              </Button>
            </div>
          </>
        )}

        {step === "recovery" && recoveryKey && (
          <>
            <p className="eyebrow">One more thing</p>
            <h1 className="mt-1.5 text-[21px] font-semibold tracking-[-0.01em]">
              Save your recovery key
            </h1>
            <p className="mt-2 leading-relaxed text-[var(--text-dim)]">
              This key unlocks your vault if you ever forget the master
              password. Keep it outside this computer — a password manager or a
              printed page. It will never be shown again.
            </p>
            <div className="mono mt-5 select-text break-all rounded-[10px] border border-dashed border-[var(--hairline-strong)] bg-[var(--field)] p-3.5 text-[12.5px] leading-relaxed tracking-wide">
              {recoveryKey}
            </div>
            <Button variant="ghost" className="mt-3 w-full" onClick={() => void copyRecoveryKey()}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? "Copied" : "Copy to clipboard"}
            </Button>
            <div className="mt-4">
              <Checkbox checked={savedRecovery} onChange={setSavedRecovery}>
                I saved my recovery key somewhere safe.
              </Checkbox>
            </div>
            <Button
              className="mt-5 w-full"
              disabled={!savedRecovery}
              onClick={() => {
                setRecoveryKey(null);
                markUnlocked(false);
              }}
            >
              Open my vault
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
