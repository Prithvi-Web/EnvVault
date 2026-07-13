// Project list. Click to select; hover exposes delete. The + button opens
// the native-folder-picker add flow owned by Home.

import { FolderLock, Plus, Trash2 } from "lucide-react";
import { useVault } from "../../store";
import { pathTail } from "../../lib/format";
import type { ProjectSummary } from "../../bindings";

interface SidebarProps {
  onAddProject: () => void;
  onDeleteProject: (project: ProjectSummary) => void;
}

export function Sidebar({ onAddProject, onDeleteProject }: SidebarProps) {
  const projects = useVault((s) => s.projects);
  const selectedId = useVault((s) => s.selectedProjectId);
  const selectProject = useVault((s) => s.selectProject);

  return (
    <aside className="sidebar">
      <div className="mb-2 flex items-center justify-between px-1.5">
        <span className="eyebrow">Projects</span>
        <button
          className="icon-btn"
          title="Add project"
          aria-label="Add project"
          onClick={onAddProject}
        >
          <Plus size={15} />
        </button>
      </div>

      {projects.length === 0 && (
        <div className="px-2 py-6 text-center text-[12px] leading-relaxed text-[var(--text-faint)]">
          No projects yet. Add the folder of a project you're working on to
          give its secrets a home.
        </div>
      )}

      <div className="flex flex-col gap-0.5">
        {projects.map((p) => (
          <button
            key={p.id}
            className="sidebar-item"
            data-selected={p.id === selectedId}
            onClick={() => selectProject(p.id)}
          >
            <FolderLock size={15} strokeWidth={1.8} className="flex-none" />
            <span className="min-w-0 flex-1">
              <span className="block truncate">{p.name}</span>
              <span className="mono block truncate text-[10px] text-[var(--text-faint)]">
                {pathTail(p.path)}
              </span>
            </span>
            <span className="row-actions flex">
              <span
                role="button"
                tabIndex={-1}
                className="icon-btn danger"
                title={`Delete ${p.name}`}
                aria-label={`Delete ${p.name}`}
                onClick={(e) => {
                  e.stopPropagation();
                  onDeleteProject(p);
                }}
              >
                <Trash2 size={13} />
              </span>
            </span>
          </button>
        ))}
      </div>
    </aside>
  );
}
