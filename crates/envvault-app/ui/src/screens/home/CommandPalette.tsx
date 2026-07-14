// ⌘K command palette: every action, reachable without the trackpad.

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  FolderPlus,
  FolderLock,
  HardDriveDownload,
  Inbox,
  KeyRound,
  KeySquare,
  Layers,
  Lock,
  Plus,
  Share2,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useVault, useSelectedProject } from "../../store";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  icon: LucideIcon;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onLock: () => void;
  onNewSecret: () => void;
  onAddProject: () => void;
  onAddEnv: () => void;
  onShowHealth: () => void;
  /** Null when the selected environment has nothing to share. */
  onShareEnv: (() => void) | null;
  onImportBundle: () => void;
  onVaultBackup: () => void;
  onShareKey: () => void;
}

export function CommandPalette({
  open,
  onClose,
  onLock,
  onNewSecret,
  onAddProject,
  onAddEnv,
  onShowHealth,
  onShareEnv,
  onImportBundle,
  onVaultBackup,
  onShareKey,
}: CommandPaletteProps) {
  const projects = useVault((s) => s.projects);
  const selectProject = useVault((s) => s.selectProject);
  const selectEnv = useVault((s) => s.selectEnv);
  const selectedEnvId = useVault((s) => s.selectedEnvId);
  const project = useSelectedProject();

  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      // Radix-free overlay: focus manually after mount.
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const actions = useMemo<PaletteAction[]>(() => {
    const list: PaletteAction[] = [
      { id: "new-secret", label: "New secret", hint: "N", icon: Plus, run: onNewSecret },
      { id: "health", label: "Secret health", icon: Activity, run: onShowHealth },
      { id: "add-project", label: "Add project", icon: FolderPlus, run: onAddProject },
      { id: "add-env", label: "Add environment", icon: Layers, run: onAddEnv },
      { id: "lock", label: "Lock vault", hint: "⌘L", icon: Lock, run: onLock },
      {
        id: "import-bundle",
        label: "Import share bundle",
        icon: Inbox,
        run: onImportBundle,
      },
      {
        id: "vault-backup",
        label: "Backup & portability",
        icon: HardDriveDownload,
        run: onVaultBackup,
      },
      { id: "share-key", label: "My share key", icon: KeyRound, run: onShareKey },
    ];
    if (onShareEnv) {
      const envName = project?.environments.find((e) => e.id === selectedEnvId)?.name;
      list.splice(1, 0, {
        id: "share-env",
        label: `Share ${envName ?? "environment"}`,
        icon: Share2,
        run: onShareEnv,
      });
    }
    for (const env of project?.environments ?? []) {
      list.push({
        id: `env-${env.id}`,
        label: `Switch to ${env.name}`,
        hint: env.isProduction ? "production" : undefined,
        icon: KeySquare,
        run: () => selectEnv(env.id),
      });
    }
    for (const p of projects) {
      list.push({
        id: `project-${p.id}`,
        label: `Go to ${p.name}`,
        icon: FolderLock,
        run: () => selectProject(p.id),
      });
    }
    return list;
  }, [
    projects,
    project,
    selectedEnvId,
    onLock,
    onNewSecret,
    onAddProject,
    onAddEnv,
    onShowHealth,
    onShareEnv,
    onImportBundle,
    onVaultBackup,
    onShareKey,
    selectEnv,
    selectProject,
  ]);

  const filtered = actions.filter((a) =>
    a.label.toLowerCase().includes(query.trim().toLowerCase()),
  );
  const clampedActive = Math.min(active, Math.max(0, filtered.length - 1));

  function runAction(action: PaletteAction) {
    onClose();
    action.run();
  }

  if (!open) return null;

  return (
    <div
      className="overlay z-40"
      onClick={onClose}
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <div
        className="palette"
        role="dialog"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          placeholder="Type a command…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((a) => Math.min(a + 1, filtered.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => Math.max(a - 1, 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              const action = filtered[clampedActive];
              if (action) runAction(action);
            }
          }}
        />
        <div className="max-h-[320px] overflow-y-auto py-1.5">
          {filtered.length === 0 && (
            <p className="px-4 py-3 text-[12.5px] text-[var(--text-faint)]">
              No matching command.
            </p>
          )}
          {filtered.map((action, idx) => {
            const Icon = action.icon;
            return (
              <button
                key={action.id}
                className="palette-item"
                data-active={idx === clampedActive}
                onMouseEnter={() => setActive(idx)}
                onClick={() => runAction(action)}
              >
                <Icon size={14} strokeWidth={1.8} className="flex-none" />
                <span className="flex-1 truncate">{action.label}</span>
                {action.hint && (
                  <span className="text-[10.5px] text-[var(--text-faint)]">{action.hint}</span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
