// In-app banner shown when the Guard catches a dangerous change (spec F6).
// Sits alongside the OS notification, and — for a newly appeared .env —
// offers the one-click Import & Secure fix.

import { ShieldAlert, X } from "lucide-react";
import type { GuardFindingEvent } from "../../bindings";
import { Button } from "../../ui/components";

interface GuardBannerProps {
  finding: GuardFindingEvent;
  onSecure: (() => void) | null;
  onDismiss: () => void;
}

export function GuardBanner({ finding, onSecure, onDismiss }: GuardBannerProps) {
  const message = describe(finding);
  return (
    <div className="rise-in mb-3 flex items-start gap-3 rounded-[10px] border border-[rgba(255,92,87,0.4)] bg-[var(--danger-soft)] px-3.5 py-2.5">
      <ShieldAlert size={16} color="var(--danger)" className="mt-0.5 flex-none" />
      <div className="min-w-0 flex-1">
        <div className="text-[12.5px] font-semibold text-[var(--danger)]">
          The Guard caught something
        </div>
        <div className="mt-0.5 text-[12px] leading-relaxed text-[var(--text-dim)]">{message}</div>
      </div>
      {finding.kind === "env-appeared" && onSecure && (
        <Button
          style={{ height: 28, background: "var(--danger)", color: "#fff" }}
          onClick={onSecure}
        >
          Import &amp; Secure
        </Button>
      )}
      <button className="icon-btn" aria-label="Dismiss" onClick={onDismiss}>
        <X size={14} />
      </button>
    </div>
  );
}

function describe(f: GuardFindingEvent): string {
  switch (f.kind) {
    case "env-appeared":
      return `A plaintext ${f.fileName} just appeared in a watched project — secure it before it can be committed.`;
    case "secret-in-file":
      return `${f.secretKeys.join(", ")} from your vault ${
        f.secretKeys.length === 1 ? "was" : "were"
      } written into ${f.fileName} in plaintext.`;
    case "gitignore-exposed":
      return ".gitignore changed and .env is no longer ignored — a commit could now leak it.";
    default:
      return "A watched project changed in a risky way.";
  }
}
