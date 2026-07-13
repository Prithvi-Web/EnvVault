// Environment switcher. Production is red — tab, dot, and the banner below.

import { Plus, X } from "lucide-react";
import { useVault, useSelectedProject } from "../../store";
import type { EnvironmentSummary } from "../../bindings";

interface EnvTabsProps {
  onAddEnv: () => void;
  onRemoveEnv: (env: EnvironmentSummary) => void;
}

export function EnvTabs({ onAddEnv, onRemoveEnv }: EnvTabsProps) {
  const project = useSelectedProject();
  const selectedEnvId = useVault((s) => s.selectedEnvId);
  const selectEnv = useVault((s) => s.selectEnv);

  if (!project) return null;

  return (
    <div className="flex items-center gap-1.5">
      {project.environments.map((env) => (
        <button
          key={env.id}
          className="env-tab"
          data-selected={env.id === selectedEnvId}
          data-production={env.isProduction}
          onClick={() => selectEnv(env.id)}
        >
          {env.isProduction && (
            <span
              className="status-dot"
              style={{ background: "var(--danger)", width: 6, height: 6 }}
            />
          )}
          {env.name}
          <span className="text-[10.5px] text-[var(--text-faint)]">{env.secretCount}</span>
          {project.environments.length > 1 && (
            <span
              role="button"
              tabIndex={-1}
              className="icon-btn -mr-1.5"
              style={{ width: 18, height: 18 }}
              title={`Remove ${env.name}`}
              aria-label={`Remove ${env.name}`}
              onClick={(e) => {
                e.stopPropagation();
                onRemoveEnv(env);
              }}
            >
              <X size={11} />
            </span>
          )}
        </button>
      ))}
      <button className="icon-btn" title="Add environment" aria-label="Add environment" onClick={onAddEnv}>
        <Plus size={14} />
      </button>
    </div>
  );
}
