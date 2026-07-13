// Add a project by picking its folder with the OS's native picker (spec F3).

import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-react";
import { commands } from "../../bindings";
import { useVault } from "../../store";
import { describeError } from "../../lib/errors";
import { Button, TextField } from "../../ui/components";
import { Modal } from "../../ui/dialog";

interface AddProjectDialogProps {
  open: boolean;
  onClose: () => void;
}

export function AddProjectDialog({ open: isOpen, onClose }: AddProjectDialogProps) {
  const loadProjects = useVault((s) => s.loadProjects);
  const selectProject = useVault((s) => s.selectProject);

  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName("");
    setPath("");
    setError(null);
  }, [isOpen]);

  async function pickFolder() {
    const selection = await open({ directory: true, multiple: false, title: "Choose the project folder" });
    if (typeof selection === "string") {
      setPath(selection);
      if (!name.trim()) {
        const tail = selection.split(/[/\\]/).filter(Boolean).pop();
        if (tail) setName(tail);
      }
    }
  }

  async function submit() {
    if (!name.trim() || !path || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.addProject(name.trim(), path);
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    await loadProjects();
    selectProject(result.data.id);
    onClose();
  }

  return (
    <Modal
      open={isOpen}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title="Add a project"
      description="Point EnvVault at a project folder. Its secrets live in the vault — never inside that folder."
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div>
          <label className="eyebrow mb-1.5 block">Folder</label>
          <div className="flex gap-2">
            <TextField
              readOnly
              placeholder="No folder chosen"
              value={path}
              className="mono flex-1 text-[11.5px]"
              tabIndex={-1}
            />
            <Button type="button" variant="ghost" onClick={() => void pickFolder()}>
              <FolderOpen size={14} />
              Choose…
            </Button>
          </div>
        </div>
        <div>
          <label className="eyebrow mb-1.5 block" htmlFor="project-name">
            Name
          </label>
          <TextField
            id="project-name"
            placeholder="my-saas-backend"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
        <div className="flex justify-end gap-2.5 pt-1">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!name.trim() || !path || busy}>
            {busy ? "Adding…" : "Add project"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
