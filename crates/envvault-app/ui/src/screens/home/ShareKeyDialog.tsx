// "My share key" — the vault's public key. Teammates encrypt share bundles
// to it. Public material: safe to paste in chat, a wiki, an email signature.

import { useEffect, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Check, Copy } from "lucide-react";
import { commands } from "../../bindings";
import { describeError } from "../../lib/errors";
import { Button } from "../../ui/components";
import { Modal } from "../../ui/dialog";

interface ShareKeyDialogProps {
  open: boolean;
  onClose: () => void;
}

export function ShareKeyDialog({ open: isOpen, onClose }: ShareKeyDialogProps) {
  const [key, setKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setKey(null);
    setError(null);
    setCopied(false);
    void commands.shareKey().then((result) => {
      if (result.status === "ok") setKey(result.data);
      else setError(describeError(result.error));
    });
  }, [isOpen]);

  async function copy() {
    if (!key) return;
    await writeText(key);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <Modal
      open={isOpen}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title="My share key"
      description="Give this to teammates. Bundles they encrypt to it can only be opened by you — unlocked with your master password. It is a public key: safe to share anywhere."
    >
      <div className="space-y-3">
        <div className="flex items-center gap-2 rounded-[9px] border border-[var(--hairline)] bg-[var(--panel)] px-3 py-2.5">
          <span className="mono min-w-0 flex-1 break-all text-[11.5px] leading-relaxed">
            {key ?? "…"}
          </span>
          <Button variant="ghost" style={{ height: 26 }} disabled={!key} onClick={() => void copy()}>
            {copied ? <Check size={13} /> : <Copy size={13} />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
        <div className="flex justify-end">
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>
    </Modal>
  );
}
