// The secret list. Values are masked by default and revealed only on an
// explicit action; production reveals take a second, deliberate confirmation.
// Revealed plaintext lives ONLY in this component's state and is dropped on
// hide, env change, unmount, and lock (spec §4.3).
//
// Keyboard: ↑/↓ move, Enter reveal/hide, ⌘C or c copy, e edit, ⌫ delete.

import { useEffect, useRef, useState } from "react";
import { Copy, Eye, EyeOff, Pencil, ShieldAlert, Trash2 } from "lucide-react";
import { commands, type SecretMeta } from "../../bindings";
import { useVault } from "../../store";
import { relativeTime } from "../../lib/format";
import { describeError } from "../../lib/errors";
import { useToasts } from "../../ui/toast";
import { ConfirmDialog } from "../../ui/dialog";

interface SecretsTableProps {
  filter: string;
  isProduction: boolean;
  onEdit: (secret: SecretMeta) => void;
  onDelete: (secret: SecretMeta) => void;
}

export function SecretsTable({ filter, isProduction, onEdit, onDelete }: SecretsTableProps) {
  const secrets = useVault((s) => s.secrets);
  const projectId = useVault((s) => s.selectedProjectId);
  const envId = useVault((s) => s.selectedEnvId);
  const push = useToasts((s) => s.push);

  // Plaintext cache for revealed rows — component-local by design.
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [pendingReveal, setPendingReveal] = useState<SecretMeta | null>(null);
  const [focusIdx, setFocusIdx] = useState(0);
  const rowRefs = useRef<(HTMLDivElement | null)[]>([]);

  // Navigating anywhere else drops all plaintext immediately.
  useEffect(() => {
    setRevealed({});
    setFocusIdx(0);
  }, [projectId, envId]);

  const visible = secrets.filter(
    (s) =>
      s.key.toLowerCase().includes(filter.toLowerCase()) ||
      (s.note ?? "").toLowerCase().includes(filter.toLowerCase()),
  );

  async function doReveal(secret: SecretMeta) {
    if (!projectId || !envId) return;
    const result = await commands.revealSecret(projectId, envId, secret.id);
    if (result.status === "ok") {
      setRevealed((r) => ({ ...r, [secret.id]: result.data }));
    } else {
      push(describeError(result.error));
    }
  }

  function toggleReveal(secret: SecretMeta) {
    if (revealed[secret.id] !== undefined) {
      setRevealed((r) => {
        const { [secret.id]: _dropped, ...rest } = r;
        return rest;
      });
      return;
    }
    // Production requires a second deliberate action (spec §7).
    if (isProduction) {
      setPendingReveal(secret);
    } else {
      void doReveal(secret);
    }
  }

  async function copy(secret: SecretMeta) {
    if (!projectId || !envId) return;
    const result = await commands.copySecret(projectId, envId, secret.id);
    if (result.status === "ok") {
      push(`Copied ${secret.key}`, result.data);
    } else {
      push(describeError(result.error));
    }
  }

  function onRowKeyDown(e: React.KeyboardEvent, secret: SecretMeta, idx: number) {
    const move = (to: number) => {
      const clamped = Math.max(0, Math.min(visible.length - 1, to));
      setFocusIdx(clamped);
      rowRefs.current[clamped]?.focus();
    };
    if (e.key === "ArrowDown") {
      e.preventDefault();
      move(idx + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      move(idx - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      toggleReveal(secret);
    } else if (e.key === "c" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void copy(secret);
    } else if (e.key === "c") {
      e.preventDefault();
      void copy(secret);
    } else if (e.key === "e") {
      e.preventDefault();
      onEdit(secret);
    } else if (e.key === "Backspace" || e.key === "Delete") {
      e.preventDefault();
      onDelete(secret);
    }
  }

  if (secrets.length === 0) {
    return (
      <div className="mt-10 flex flex-col items-center rounded-2xl border border-dashed border-[var(--hairline-strong)] p-10 text-center">
        <h3 className="text-[14.5px] font-semibold">No secrets in this environment</h3>
        <p className="mt-1.5 max-w-[360px] text-[12.5px] leading-relaxed text-[var(--text-dim)]">
          Press <kbd>N</kbd> to add your first secret, or wait for Import
          &amp; Secure in the next phase to pull in an existing{" "}
          <span className="mono">.env</span> automatically.
        </p>
      </div>
    );
  }

  return (
    <div role="list" aria-label="Secrets">
      {visible.length === 0 && (
        <p className="mt-8 text-center text-[12.5px] text-[var(--text-faint)]">
          Nothing matches “{filter}”.
        </p>
      )}
      {visible.map((secret, idx) => {
        const plaintext = revealed[secret.id];
        const isRevealed = plaintext !== undefined;
        return (
          <div
            key={secret.id}
            ref={(el) => {
              rowRefs.current[idx] = el;
            }}
            role="listitem"
            tabIndex={idx === focusIdx ? 0 : -1}
            className="secret-row"
            onKeyDown={(e) => onRowKeyDown(e, secret, idx)}
            onFocus={() => setFocusIdx(idx)}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="mono truncate text-[12.5px] font-medium">{secret.key}</span>
                {secret.detectedLabel && <span className="badge">{secret.detectedLabel}</span>}
              </div>
              {secret.note && (
                <div className="mt-0.5 truncate text-[11px] text-[var(--text-faint)]">
                  {secret.note}
                </div>
              )}
            </div>

            <div className="mono min-w-0 truncate text-[12px]">
              {isRevealed ? (
                <span className="select-text break-all">{plaintext}</span>
              ) : (
                <span className="masked-dots" aria-label="hidden value">
                  {"•".repeat(Math.min(Math.max(secret.valueLength, 6), 24))}
                </span>
              )}
            </div>

            <div className="flex items-center gap-1">
              <span className="mr-2 hidden text-[10.5px] text-[var(--text-faint)] lg:inline">
                {relativeTime(secret.rotatedAt)}
              </span>
              <span className="row-actions flex items-center gap-1">
                <button
                  className="icon-btn"
                  title={isRevealed ? "Hide value" : "Reveal value"}
                  aria-label={isRevealed ? `Hide ${secret.key}` : `Reveal ${secret.key}`}
                  onClick={() => toggleReveal(secret)}
                >
                  {isRevealed ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <button
                  className="icon-btn"
                  title="Copy value (clears in 30s)"
                  aria-label={`Copy ${secret.key}`}
                  onClick={() => void copy(secret)}
                >
                  <Copy size={14} />
                </button>
                <button
                  className="icon-btn"
                  title="Edit"
                  aria-label={`Edit ${secret.key}`}
                  onClick={() => onEdit(secret)}
                >
                  <Pencil size={14} />
                </button>
                <button
                  className="icon-btn danger"
                  title="Delete"
                  aria-label={`Delete ${secret.key}`}
                  onClick={() => onDelete(secret)}
                >
                  <Trash2 size={14} />
                </button>
              </span>
            </div>
          </div>
        );
      })}

      <ConfirmDialog
        open={pendingReveal !== null}
        onOpenChange={(open) => {
          if (!open) setPendingReveal(null);
        }}
        title="Reveal a production secret?"
        body={`This is production. ${pendingReveal?.key ?? ""} will be visible on screen until you hide it.`}
        confirmLabel="Reveal it"
        danger
        onConfirm={() => {
          if (pendingReveal) void doReveal(pendingReveal);
          setPendingReveal(null);
        }}
      />
      {isProduction && (
        <div className="mt-4 flex justify-center">
          <span className="flex items-center gap-1.5 text-[10.5px] text-[var(--text-faint)]">
            <ShieldAlert size={11} color="var(--danger)" />
            Production values need a confirmation to reveal.
          </span>
        </div>
      )}
    </div>
  );
}
