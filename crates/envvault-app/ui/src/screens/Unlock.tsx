// The lock screen. A locked vault looks locked: one glass card, one field.
// Accepts the master password or a recovery key. Wrong attempts shake and
// count down toward the 5-minute lockout; rate limiting shows a live timer.

import { useEffect, useRef, useState } from "react";
import { Lock } from "lucide-react";
import { commands } from "../bindings";
import { useVault } from "../store";
import { describeError, formatSeconds } from "../lib/errors";
import { Button, TextField } from "../ui/components";

export default function Unlock() {
  const markUnlocked = useVault((s) => s.markUnlocked);
  const vaultPath = useVault((s) => s.vaultPath);

  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shaking, setShaking] = useState(false);
  const [retryIn, setRetryIn] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Live countdown while rate-limited; re-enables the field at zero.
  useEffect(() => {
    if (retryIn <= 0) return;
    const t = setInterval(() => setRetryIn((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(t);
  }, [retryIn > 0]);

  useEffect(() => {
    if (retryIn === 0) inputRef.current?.focus();
  }, [retryIn === 0]);

  async function submit() {
    if (!passphrase || busy || retryIn > 0) return;
    setBusy(true);
    setError(null);
    const result = await commands.unlock(passphrase);
    setBusy(false);
    if (result.status === "ok") {
      setPassphrase("");
      markUnlocked(result.data.viaRecovery);
      return;
    }
    const err = result.error;
    setError(describeError(err));
    if (err.kind === "RateLimited") {
      setRetryIn(err.detail.retryAfterSeconds);
    } else if (err.kind === "WrongPassword") {
      setShaking(true);
      setTimeout(() => setShaking(false), 450);
      setPassphrase("");
      inputRef.current?.focus();
    }
  }

  return (
    <div className="flex flex-1 items-center justify-center p-8" data-tauri-drag-region>
      <div className={`glass-card rise-in w-[400px] p-8 ${shaking ? "shake" : ""}`}>
        <div className="flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full border border-[var(--hairline)] bg-[var(--panel)]">
            <Lock size={20} color="var(--text-dim)" strokeWidth={1.8} />
          </div>
          <h1 className="mt-4 text-[19px] font-semibold tracking-[-0.01em]">
            EnvVault is locked
          </h1>
          <p className="mt-1 text-[var(--text-dim)]">
            Enter your master password to open your vault.
          </p>
        </div>

        <form
          className="mt-6"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <TextField
            ref={inputRef}
            type="password"
            placeholder={retryIn > 0 ? `Locked — try again in ${formatSeconds(retryIn)}` : "Master password or recovery key"}
            value={passphrase}
            autoFocus
            disabled={busy || retryIn > 0}
            hasError={error !== null && retryIn === 0}
            onChange={(e) => {
              setPassphrase(e.target.value);
              setError(null);
            }}
          />
          {error && (
            <p className="mt-2.5 text-[12.5px] leading-snug text-[var(--danger)]" role="alert">
              {error}
            </p>
          )}
          <Button
            type="submit"
            className="mt-4 w-full"
            disabled={!passphrase || busy || retryIn > 0}
          >
            {busy ? "Unlocking…" : retryIn > 0 ? `Try again in ${formatSeconds(retryIn)}` : "Unlock"}
          </Button>
        </form>

        <p className="mono mt-6 truncate text-center text-[10.5px] text-[var(--text-faint)]" title={vaultPath}>
          {vaultPath}
        </p>
      </div>
    </div>
  );
}
