// Styled Radix dialog wrappers: accessible focus-trapped modals on the glass
// design system. Esc closes; the overlay dims and blurs.

import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
import { Button } from "./components";

interface ModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  danger?: boolean;
}

export function Modal({ open, onOpenChange, title, description, children, danger }: ModalProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content
          className="dialog-panel"
          onOpenAutoFocus={(e) => {
            // Focus the first field, not the close button.
            const el = (e.currentTarget as HTMLElement | null)?.querySelector<HTMLElement>(
              "input, textarea, button.btn-primary",
            );
            if (el) {
              e.preventDefault();
              el.focus();
            }
          }}
        >
          <Dialog.Title
            className="text-[15px] font-semibold tracking-[-0.01em]"
            style={danger ? { color: "var(--danger)" } : undefined}
          >
            {title}
          </Dialog.Title>
          {description ? (
            <Dialog.Description className="mt-1.5 text-[12.5px] leading-relaxed text-[var(--text-dim)]">
              {description}
            </Dialog.Description>
          ) : (
            // Radix warns without a description; render an empty one.
            <Dialog.Description className="hidden" />
          )}
          <div className="mt-4">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  body: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel,
  danger = false,
  onConfirm,
}: ConfirmDialogProps) {
  return (
    <Modal open={open} onOpenChange={onOpenChange} title={title} description={body} danger={danger}>
      <div className="flex justify-end gap-2.5">
        <Button variant="ghost" onClick={() => onOpenChange(false)}>
          Cancel
        </Button>
        <Button
          autoFocus
          style={danger ? { background: "var(--danger)", color: "#fff" } : undefined}
          onClick={() => {
            onConfirm();
            onOpenChange(false);
          }}
        >
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
