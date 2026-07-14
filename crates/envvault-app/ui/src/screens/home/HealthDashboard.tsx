// Secret health dashboard (spec F7): stale, reused, weak, and git-exposed
// findings — worst first — each with a specific, actionable fix. Values are
// never shown here; only names and finding metadata cross the boundary.

import { useEffect, useState } from "react";
import {
  Clock,
  Copy,
  ExternalLink,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { commands, type HealthFinding, type HealthReport } from "../../bindings";
import { describeError } from "../../lib/errors";
import { useToasts } from "../../ui/toast";

const CATEGORY: Record<
  HealthFinding["category"],
  { icon: LucideIcon; label: string }
> = {
  exposed: { icon: ShieldAlert, label: "Exposed in git" },
  weak: { icon: KeyRound, label: "Weak" },
  reused: { icon: Copy, label: "Reused" },
  stale: { icon: Clock, label: "Stale" },
};

export function HealthDashboard() {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const push = useToasts((s) => s.push);

  useEffect(() => {
    void commands.healthReport().then((r) => {
      if (r.status === "ok") setReport(r.data);
      else setError(describeError(r.error));
    });
  }, []);

  if (error) {
    return <p className="mt-10 text-center text-[13px] text-[var(--danger)]">{error}</p>;
  }
  if (!report) {
    return (
      <p className="mt-10 text-center text-[12.5px] text-[var(--text-faint)]">Analyzing…</p>
    );
  }

  const clean = report.findings.length === 0;

  return (
    <div className="mx-auto w-full max-w-[720px]">
      <div className="mb-4 flex items-center gap-3">
        <h2 className="text-[16px] font-semibold tracking-[-0.01em]">Secret health</h2>
        <div className="flex gap-1.5">
          {report.criticalCount > 0 && (
            <span className="badge" style={{ borderColor: "rgba(255,92,87,0.4)", color: "var(--danger)" }}>
              {report.criticalCount} critical
            </span>
          )}
          {report.warningCount > 0 && (
            <span className="badge" style={{ borderColor: "rgba(255,190,76,0.4)", color: "var(--warn)" }}>
              {report.warningCount} warning
            </span>
          )}
          <span className="badge">{report.totalSecrets} secrets scanned</span>
        </div>
      </div>

      {clean ? (
        <div className="rise-in flex flex-col items-center rounded-2xl border border-dashed border-[var(--hairline-strong)] p-12 text-center">
          <ShieldCheck size={30} color="var(--ok)" strokeWidth={1.6} />
          <h3 className="mt-3 text-[15px] font-semibold">Everything looks healthy</h3>
          <p className="mt-1.5 max-w-[400px] text-[12.5px] leading-relaxed text-[var(--text-dim)]">
            No stale, reused, weak, or git-exposed secrets. EnvVault re-checks
            every time you open this view.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {report.findings.map((f, i) => (
            <FindingCard key={i} finding={f} onCopyUrl={(url) => {
              void navigator.clipboard?.writeText(url);
              push("Rotation link copied");
            }} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({
  finding,
  onCopyUrl,
}: {
  finding: HealthFinding;
  onCopyUrl: (url: string) => void;
}) {
  const cat = CATEGORY[finding.category] ?? { icon: ShieldAlert, label: finding.category };
  const Icon = cat.icon;
  const critical = finding.severity === "critical";
  const accent = critical ? "var(--danger)" : "var(--warn)";
  const bg = critical ? "var(--danger-soft)" : "rgba(255,190,76,0.08)";
  const border = critical ? "rgba(255,92,87,0.35)" : "rgba(255,190,76,0.3)";

  return (
    <div
      className="rise-in rounded-[11px] border p-4"
      style={{ borderColor: border, background: bg }}
    >
      <div className="flex items-start gap-3">
        <div
          className="mt-0.5 flex h-7 w-7 flex-none items-center justify-center rounded-lg"
          style={{ background: "rgba(0,0,0,0.2)" }}
        >
          <Icon size={15} color={accent} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold" style={{ color: accent }}>
              {finding.title}
            </span>
            <span className="badge">{cat.label}</span>
          </div>

          <div className="mono mt-1.5 flex flex-wrap gap-1.5">
            {finding.locations.map((l) => (
              <span
                key={l.secretId}
                className="badge"
                style={
                  l.isProduction
                    ? { borderColor: "rgba(255,92,87,0.4)", color: "var(--danger)" }
                    : undefined
                }
                title={`${l.projectName} → ${l.environmentName}`}
              >
                {l.projectName}/{l.environmentName}/{l.secretKey}
              </span>
            ))}
          </div>

          <p className="mt-2 text-[12px] leading-relaxed text-[var(--text-dim)]">{finding.fix}</p>

          {finding.fixUrl && (
            <button
              className="mono mt-1.5 inline-flex items-center gap-1.5 text-[11.5px] text-[var(--accent)]"
              onClick={() => onCopyUrl(finding.fixUrl)}
              title="Copy the rotation link (EnvVault never opens the network)"
            >
              <ExternalLink size={11} />
              {finding.fixUrl}
              <Copy size={10} className="opacity-60" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
