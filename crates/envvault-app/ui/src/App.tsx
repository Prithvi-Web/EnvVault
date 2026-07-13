import { useEffect, useState } from "react";
import { commands, type AppInfo, type AppError } from "./bindings";

/**
 * Phase 0 shell: proves the typed IPC pipeline end-to-end.
 * The real UI (unlock screen, vault views) lands in Phases 2–3.
 */
export default function App() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    commands.appInfo().then((result) => {
      if (result.status === "ok") {
        setInfo(result.data);
      } else {
        setError(describeError(result.error));
      }
    });
  }, []);

  return (
    <main className="flex h-screen flex-col items-center justify-center gap-3 bg-neutral-950 text-neutral-100">
      <h1 className="text-2xl font-semibold tracking-tight">EnvVault</h1>
      {info && (
        <div className="text-center text-sm text-neutral-400">
          <p>v{info.version} — typed IPC bridge is live</p>
          <p className="mt-1 font-mono text-xs">
            vault: {info.vaultPath} ({info.vaultExists ? "exists" : "not created yet"})
          </p>
        </div>
      )}
      {error && <p className="text-sm text-red-400">{error}</p>}
    </main>
  );
}

function describeError(e: AppError): string {
  switch (e.kind) {
    case "VaultLocked":
      return "The vault is locked.";
    case "WrongPassword":
      return `Wrong password (${e.detail.attemptsRemaining} attempts remaining).`;
    case "VaultCorrupted":
      return `Vault file corrupted at ${e.detail.path}.`;
    case "VaultNotFound":
      return "No vault exists yet.";
    case "VaultAlreadyExists":
      return `A vault already exists at ${e.detail.path}.`;
    case "ProjectNotFound":
      return `No project registered for ${e.detail.path}.`;
    case "SecretNameTaken":
      return `A secret named ${e.detail.name} already exists.`;
    case "IoError":
      return `I/O error: ${e.detail.message}`;
    case "NoDataDir":
      return "Could not find the application data directory.";
    default: {
      // Exhaustiveness guard: a new Rust error variant that is not handled
      // above makes this assignment — and therefore the build — fail.
      const unhandled: never = e;
      return `Unhandled error: ${JSON.stringify(unhandled)}`;
    }
  }
}
