// About EnvVault (spec §4.7): states — truthfully — that the app makes no
// network requests and contains no networking code. This is enforced, not
// aspirational: the CSP allows no remote origin, and CI fails the build if
// any HTTP client crate enters the shipped dependency graph.

import { WifiOff } from "lucide-react";
import { useVault } from "../../store";
import { Button } from "../../ui/components";
import { Modal } from "../../ui/dialog";

interface AboutDialogProps {
  open: boolean;
  onClose: () => void;
}

export function AboutDialog({ open: isOpen, onClose }: AboutDialogProps) {
  const appVersion = useVault((s) => s.appVersion);
  const vaultPath = useVault((s) => s.vaultPath);

  return (
    <Modal
      open={isOpen}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={`EnvVault ${appVersion ? `v${appVersion}` : ""}`}
      description="A fully local secrets manager. Your secrets live in one encrypted vault on this computer — not in your repo, not in the cloud."
    >
      <div className="space-y-3">
        <div className="flex items-start gap-2.5 rounded-[9px] border border-[var(--hairline)] bg-[var(--panel)] px-3 py-2.5">
          <WifiOff size={15} className="mt-0.5 flex-none" color="var(--ok)" />
          <p className="text-[12.5px] leading-relaxed text-[var(--text-dim)]">
            <span className="font-medium text-[var(--text)]">
              EnvVault has made 0 network requests. It contains no networking code.
            </span>{" "}
            This is enforced, not promised: the app's content-security policy allows no
            remote origin, and the build fails if any HTTP library enters the dependency
            tree. It works in airplane mode, forever.
          </p>
        </div>

        <p className="text-[12px] leading-relaxed text-[var(--text-faint)]">
          Encrypted with <span className="mono">age</span>. Your data is never hostage —
          the vault at <span className="mono text-[11px]">{vaultPath}</span> is a standard
          age file you can decrypt without this app (the README shows how). What EnvVault
          does and does not protect against is documented honestly in SECURITY.md and
          LIMITATIONS.md.
        </p>

        <div className="flex justify-end pt-1">
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>
    </Modal>
  );
}
