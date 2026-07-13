// The unlocked shell. Phase 2 keeps it minimal: lock state is always visible,
// ⌘L locks instantly, and a recovery-key session demands a new password.
// The project sidebar and secret list arrive in Phase 3.

import { useEffect, useState } from "react";
import { LockOpen, KeyRound } from "lucide-react";
import { commands } from "../bindings";
import { useVault } from "../store";
import { describeError } from "../lib/errors";
import {
  loadScorer,
  scorePassword,
  REQUIRED_SCORE,
  type Strength,
} from "../lib/password";
import { Button, StrengthMeter, TextField } from "../ui/components";

export default function Home() {
  const { viaRecovery, autoLockMinutes, appVersion, refresh, markLocked } = useVault();

  async function lock() {
    const result = await commands.lockVault();
    if (result.status === "ok") markLocked();
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
          <Button variant="ghost" onClick={() => void lock()}>
            <LockOpen size={14} />
            Lock
            <kbd>⌘L</kbd>
          </Button>
        </div>
      </header>

      <main className="flex flex-1 flex-col items-center justify-center gap-6 p-8">
        {viaRecovery && <RekeyBanner onDone={() => void refresh()} />}
        <div className="rise-in flex w-[440px] flex-col items-center rounded-2xl border border-dashed border-[var(--hairline-strong)] p-10 text-center">
          <h2 className="text-[16px] font-semibold tracking-[-0.01em]">
            Your vault is ready
          </h2>
          <p className="mt-1.5 leading-relaxed text-[var(--text-dim)]">
            Projects, environments, and secrets arrive in the next build phase.
            Everything you store will be encrypted the moment it's saved.
          </p>
        </div>
        <span className="text-[10.5px] text-[var(--text-faint)]">v{appVersion}</span>
      </main>
    </>
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
    <div className="rise-in w-[440px] rounded-2xl border border-[rgba(255,190,76,0.35)] bg-[rgba(255,190,76,0.08)] p-5">
      <div className="flex items-center gap-2.5">
        <KeyRound size={16} color="var(--warn)" />
        <h2 className="text-[13.5px] font-semibold">
          You unlocked with your recovery key
        </h2>
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
