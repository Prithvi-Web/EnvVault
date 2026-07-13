import type { AppError } from "../bindings";

/**
 * Human wording for every boundary error. The `never` default arm makes this
 * switch exhaustive: adding a Rust error variant without handling it here
 * fails the TypeScript build.
 */
export function describeError(e: AppError): string {
  switch (e.kind) {
    case "VaultLocked":
      return "The vault is locked. Unlock it and try again.";
    case "WrongPassword": {
      const n = e.detail.attemptsRemaining;
      if (n === null) return "Wrong password.";
      if (n === 0) return "Wrong password. The vault is now locked for 5 minutes.";
      return `Wrong password. ${n} ${n === 1 ? "attempt" : "attempts"} left before a 5-minute lockout.`;
    }
    case "RateLimited":
      return `Too many attempts. Try again in ${formatSeconds(e.detail.retryAfterSeconds)}.`;
    case "VaultCorrupted":
      return `The vault file is damaged. Backups are next to it at ${e.detail.path}.`;
    case "VaultNotFound":
      return "No vault exists yet.";
    case "VaultAlreadyExists":
      return `A vault already exists at ${e.detail.path}.`;
    case "ProjectNotFound":
      return `No project is registered for ${e.detail.path}.`;
    case "SecretNameTaken":
      return `A secret named ${e.detail.name} already exists here.`;
    case "IoError":
      return `Something went wrong on disk: ${e.detail.message}`;
    case "NoDataDir":
      return "Could not find this computer's application data folder.";
    default: {
      const unhandled: never = e;
      return `Unexpected error: ${JSON.stringify(unhandled)}`;
    }
  }
}

export function formatSeconds(total: number): string {
  if (total < 60) return `${total}s`;
  const m = Math.floor(total / 60);
  const s = total % 60;
  return s === 0 ? `${m}m` : `${m}m ${s}s`;
}
