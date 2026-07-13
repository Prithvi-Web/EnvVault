// Shared controls. Deliberately small: styling lives in index.css classes so
// the design system has one source of truth.

import {
  forwardRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";
import { REQUIRED_SCORE, SCORE_LABELS, type Strength } from "../lib/password";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost";
}

export function Button({ variant = "primary", className = "", ...rest }: ButtonProps) {
  return (
    <button
      className={`btn ${variant === "primary" ? "btn-primary" : "btn-ghost"} ${className}`}
      {...rest}
    />
  );
}

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  hasError?: boolean;
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(
  function TextField({ hasError = false, className = "", ...rest }, ref) {
    return (
      <input
        ref={ref}
        className={`field ${hasError ? "field-error" : ""} ${className}`}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        {...rest}
      />
    );
  },
);

interface CheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  children: ReactNode;
}

export function Checkbox({ checked, onChange, children }: CheckboxProps) {
  return (
    <label className="flex cursor-default items-start gap-2.5 text-[13px] leading-snug text-[var(--text-dim)]">
      <input
        type="checkbox"
        className="check mt-0.5"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{children}</span>
    </label>
  );
}

const SCORE_COLORS = [
  "var(--danger)",
  "var(--danger)",
  "var(--warn)",
  "var(--ok)",
  "var(--ok)",
] as const;

export function StrengthMeter({ strength }: { strength: Strength | null }) {
  const score = strength?.score ?? null;
  return (
    <div aria-live="polite">
      <div className="flex gap-1.5">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className="h-[3px] flex-1 rounded-full transition-colors duration-150"
            style={{
              background:
                score !== null && i < score
                  ? SCORE_COLORS[score]
                  : "rgba(255,255,255,0.10)",
            }}
          />
        ))}
      </div>
      <div className="mt-1.5 flex items-baseline justify-between text-[11.5px]">
        <span style={{ color: score !== null ? SCORE_COLORS[score] : "var(--text-faint)" }}>
          {score !== null ? SCORE_LABELS[score] : " "}
          {score !== null && score < REQUIRED_SCORE ? " — not enough for a vault" : ""}
        </span>
        <span className="text-[var(--text-faint)]">
          {strength?.warning ?? ""}
        </span>
      </div>
    </div>
  );
}
