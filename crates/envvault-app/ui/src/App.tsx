// Shell: routes by vault state, wires the auto-lock event, the ⌘L shortcut,
// and the (throttled) activity signal that defers auto-lock.

import { useEffect, useRef } from "react";
import { commands, events } from "./bindings";
import { useVault } from "./store";
import Onboarding from "./screens/Onboarding";
import Unlock from "./screens/Unlock";
import Home from "./screens/Home";

export default function App() {
  const status = useVault((s) => s.status);
  const refresh = useVault((s) => s.refresh);
  const markLocked = useVault((s) => s.markLocked);
  const lastTouch = useRef(0);

  useEffect(() => {
    void refresh();

    // Rust locked the vault (idle timeout): drop everything, show the lock.
    const unlisten = events.vaultLockedEvent.listen(() => markLocked());

    // ⌘L / Ctrl+L locks instantly, from anywhere.
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "l") {
        e.preventDefault();
        void commands.lockVault().then((r) => {
          if (r.status === "ok") markLocked();
        });
      }
      touch();
    }

    // Real user activity defers auto-lock; throttled to one ping / 25s.
    function touch() {
      const now = Date.now();
      if (now - lastTouch.current > 25_000) {
        lastTouch.current = now;
        void commands.touchActivity();
      }
    }

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("pointerdown", touch);
    window.addEventListener("pointermove", touch);
    return () => {
      void unlisten.then((fn) => fn());
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("pointermove", touch);
    };
  }, [refresh, markLocked]);

  return (
    <div className="app-shell">
      {status === "loading" && null}
      {status === "no-vault" && <Onboarding />}
      {status === "locked" && <Unlock />}
      {status === "unlocked" && <Home />}
    </div>
  );
}
