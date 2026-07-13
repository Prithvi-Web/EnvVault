// Minimal toast system. The copy toast carries a live countdown so the
// 30-second clipboard auto-clear is visible, not mysterious (spec §4.6).

import { create } from "zustand";

export interface Toast {
  id: number;
  message: string;
  /** Seconds remaining; rendered live when present. */
  countdown?: number;
}

interface ToastStore {
  toasts: Toast[];
  push: (message: string, countdownSeconds?: number) => void;
  dismiss: (id: number) => void;
}

let nextId = 1;

export const useToasts = create<ToastStore>((set, get) => ({
  toasts: [],

  push: (message, countdownSeconds) => {
    const id = nextId++;
    set((s) => ({ toasts: [...s.toasts, { id, message, countdown: countdownSeconds }] }));

    if (countdownSeconds !== undefined) {
      const tick = setInterval(() => {
        const toast = get().toasts.find((t) => t.id === id);
        if (!toast || toast.countdown === undefined || toast.countdown <= 1) {
          clearInterval(tick);
          get().dismiss(id);
          return;
        }
        set((s) => ({
          toasts: s.toasts.map((t) =>
            t.id === id ? { ...t, countdown: (t.countdown ?? 1) - 1 } : t,
          ),
        }));
      }, 1000);
    } else {
      setTimeout(() => get().dismiss(id), 2800);
    }
  },

  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-5 z-50 flex flex-col items-center gap-2">
      {toasts.map((t) => (
        <div key={t.id} className="toast rise-in" role="status">
          {t.message}
          {t.countdown !== undefined && (
            <span className="ml-1.5 text-[var(--text-faint)]">
              — clipboard clears in {t.countdown}s
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
