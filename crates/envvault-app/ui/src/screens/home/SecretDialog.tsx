// Add/edit a secret. The value field is a textarea (multi-line values like
// PEM keys are normal). On edit, leaving the value empty keeps the current
// one — the existing value is never echoed back into the form.

import { useEffect, useState } from "react";
import { commands, type SecretMeta } from "../../bindings";
import { useVault } from "../../store";
import { describeError } from "../../lib/errors";
import { Button, TextField } from "../../ui/components";
import { Modal } from "../../ui/dialog";

export type SecretDialogMode = { mode: "new" } | { mode: "edit"; secret: SecretMeta };

interface SecretDialogProps {
  state: SecretDialogMode | null;
  onClose: () => void;
}

export function SecretDialog({ state, onClose }: SecretDialogProps) {
  const projectId = useVault((s) => s.selectedProjectId);
  const envId = useVault((s) => s.selectedEnvId);
  const loadSecrets = useVault((s) => s.loadSecrets);
  const loadProjects = useVault((s) => s.loadProjects);

  const editing = state?.mode === "edit" ? state.secret : null;
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setKey(editing?.key ?? "");
    setNote(editing?.note ?? "");
    setValue("");
    setError(null);
  }, [state]);

  const canSubmit =
    key.trim().length > 0 && (editing ? true : value.length > 0) && !busy;

  async function submit() {
    if (!projectId || !envId || !canSubmit) return;
    setBusy(true);
    setError(null);

    const result = editing
      ? await commands.updateSecret(
          projectId,
          envId,
          editing.id,
          key !== editing.key ? key : null,
          value.length > 0 ? value : null,
          note !== (editing.note ?? "") ? note : null,
        )
      : await commands.addSecret(projectId, envId, key, value, note.length > 0 ? note : null);

    setBusy(false);
    if (result.status === "error") {
      setError(describeError(result.error));
      return;
    }
    setValue("");
    await Promise.all([loadSecrets(), loadProjects()]);
    onClose();
  }

  return (
    <Modal
      open={state !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={editing ? `Edit ${editing.key}` : "New secret"}
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div>
          <label className="eyebrow mb-1.5 block" htmlFor="secret-key">
            Name
          </label>
          <TextField
            id="secret-key"
            className="mono"
            placeholder="STRIPE_SECRET_KEY"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </div>
        <div>
          <label className="eyebrow mb-1.5 block" htmlFor="secret-value">
            Value
          </label>
          <textarea
            id="secret-value"
            className="field mono min-h-[64px] resize-y py-2 leading-relaxed"
            placeholder={editing ? "Leave empty to keep the current value" : "Paste the secret value"}
            value={value}
            rows={2}
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <div>
          <label className="eyebrow mb-1.5 block" htmlFor="secret-note">
            Note <span className="normal-case tracking-normal">(optional)</span>
          </label>
          <TextField
            id="secret-note"
            placeholder="What is this for?"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
        {error && <p className="text-[12.5px] text-[var(--danger)]">{error}</p>}
        <div className="flex justify-end gap-2.5 pt-1">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!canSubmit}>
            {busy ? "Saving…" : editing ? "Save changes" : "Add secret"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
