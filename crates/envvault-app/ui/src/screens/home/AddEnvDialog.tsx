// Add an environment to the selected project.

import { useEffect, useState } from "react";
import { commands } from "../../bindings";
import { useVault } from "../../store";
import { describeError } from "../../lib/errors";
import { Button, Checkbox, TextField } from "../../ui/components";
import { Modal } from "../../ui/dialog";

interface AddEnvDialogProps {
  open: boolean;
  onClose: () => void;
}

export function AddEnvDialog({ open, onClose }: AddEnvDialogProps) {
  const projectId = useVault((s) => s.selectedProjectId);
  const loadProjects = useVault((s) => s.loadProjects);

  const [name, setName] = useState("");
  const [isProduction, setIsProduction] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName("");
    setIsProduction(false);
    setError(null);
  }, [open]);

  async function submit() {
    if (!projectId || !name.trim() || busy) return;
    setBusy(true);
    setError(null);
    const result = await commands.addEnvironment(projectId, name.trim(), isProduction);
    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    await loadProjects();
    onClose();
  }

  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title="Add an environment"
    >
      <form
        className="space-y-3.5"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <TextField
          placeholder="staging"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <Checkbox checked={isProduction} onChange={setIsProduction}>
          This is a <span style={{ color: "var(--danger)" }}>production</span>{" "}
          environment — extra confirmation required to reveal its secrets.
        </Checkbox>
        {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
        <div className="flex justify-end gap-2.5 pt-1">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!name.trim() || busy}>
            {busy ? "Adding…" : "Add environment"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
