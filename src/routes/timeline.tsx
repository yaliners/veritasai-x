import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { RiskBadge } from "@/components/veritas/risk-badge";
import { EmptyState } from "@/components/veritas/empty-state";
import { useThreats, useExtensionInstalled } from "@/lib/veritas/store";
import { Clock, Filter, AlertTriangle, ShieldCheck, HelpCircle } from "lucide-react";
import type { ThreatRecord, Risk } from "@/lib/veritas/types";

export const Route = createFileRoute("/timeline")({
  head: () => ({
    meta: [
      { title: "Chronological Timeline — VeritasShield AI" },
      { name: "description", content: "Historical threat scan events ordered chronologically." },
    ],
  }),
  component: ChronologicalTimeline,
});

function ChronologicalTimeline() {
  const [threats] = useThreats();
  const isExtensionInstalled = useExtensionInstalled();
  const [filter, setFilter] = useState<Risk | "ALL">("ALL");

  const sortedThreats = useMemo(() => {
    return [...threats]
      .filter((t) => (filter === "ALL" ? true : t.risk === filter))
      .sort((a, b) => b.timestamp - a.timestamp);
  }, [threats, filter]);

  const riskColors: Record<Risk, { dot: string; glow: string; border: string }> = {
    DANGEROUS: {
      dot: "bg-cyber-danger",
      glow: "shadow-[0_0_12px_rgba(239,68,68,0.5)]",
      border: "border-cyber-danger/30",
    },
    SUSPICIOUS: {
      dot: "bg-cyber-warning",
      glow: "shadow-[0_0_12px_rgba(245,158,11,0.5)]",
      border: "border-cyber-warning/30",
    },
    SAFE: {
      dot: "bg-cyber-success",
      glow: "shadow-[0_0_12px_rgba(34,197,94,0.5)]",
      border: "border-cyber-success/30",
    },
    TRUSTED: {
      dot: "bg-cyber-cyan",
      glow: "shadow-[0_0_12px_rgba(6,182,212,0.5)]",
      border: "border-cyber-cyan/30",
    },
  };

  const formatTime = (ts: number) => {
    return new Date(ts).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const formatDate = (ts: number) => {
    return new Date(ts).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  return (
    <>
      <Topbar
        title="Threat History Timeline"
        subtitle="Chronological flow of scanned navigations and threat detections"
      />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        {!isExtensionInstalled ? (
          <EmptyState isInstalled={isExtensionInstalled} />
        ) : threats.length === 0 ? (
          <div className="glass rounded-2xl p-12 text-center flex flex-col items-center justify-center">
            <Clock className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No timeline data</h3>
            <p className="text-sm text-muted-foreground max-w-md">
              Start browsing with the VeritasShield extension active to record threat scan history.
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Filter controls */}
            <div className="flex flex-wrap gap-2 items-center glass p-4 rounded-xl">
              <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5 mr-2">
                <Filter className="h-3.5 w-3.5" /> Filter by Risk:
              </span>
              {(["ALL", "DANGEROUS", "SUSPICIOUS", "SAFE", "TRUSTED"] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setFilter(r)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition-all ${
                    filter === r
                      ? "bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan shadow-[var(--shadow-glow)]"
                      : "bg-card/45 border-border/60 text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {r === "ALL" ? "All Scans" : r}
                </button>
              ))}
            </div>

            {sortedThreats.length === 0 ? (
              <div className="text-center py-12 glass rounded-2xl">
                <p className="text-sm text-muted-foreground">
                  No events found matching the selected filter.
                </p>
              </div>
            ) : (
              <div className="relative pl-6 md:pl-8 border-l border-border/60 ml-4 py-2 space-y-8">
                {sortedThreats.map((t, idx) => {
                  const colors = riskColors[t.risk] || riskColors.SAFE;
                  const primaryReason = t.reasons?.[0] || "No threat signals detected";

                  return (
                    <div key={t.id} className="relative group">
                      {/* Timeline point */}
                      <span
                        className={`absolute -left-[31px] md:-left-[39px] top-1.5 flex h-4 w-4 rounded-full border-2 border-background ${colors.dot} ${colors.glow} z-10 transition-transform group-hover:scale-125`}
                      />

                      {/* Event container */}
                      <div
                        className={`glass rounded-xl p-4 md:p-6 transition-all duration-300 hover:border-cyber-cyan/35 hover:shadow-[0_4px_20px_rgba(6,182,212,0.06)]`}
                      >
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                          {/* Left context */}
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-xs font-semibold text-muted-foreground">
                                {formatDate(t.timestamp)} at {formatTime(t.timestamp)}
                              </span>
                              <RiskBadge risk={t.risk} />
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-secondary/80 font-mono text-muted-foreground">
                                {t.module}
                              </span>
                            </div>
                            <h3 className="text-sm md:text-base font-semibold text-foreground tracking-tight break-all">
                              {t.domain}
                            </h3>
                            <p className="text-xs text-muted-foreground font-mono truncate max-w-xl">
                              {t.url}
                            </p>
                          </div>

                          {/* Right score indicator */}
                          <div className="flex items-center gap-4 shrink-0">
                            <div className="text-left md:text-right">
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                Threat Score
                              </p>
                              <p className="text-xl md:text-2xl font-bold font-mono text-cyber-warning">
                                {t.score}
                              </p>
                            </div>
                            <div className="h-10 w-px bg-border/60" />
                            <div className="text-left">
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                Trust Index
                              </p>
                              <p className="text-xl md:text-2xl font-bold font-mono text-cyber-success">
                                {t.trustScore}
                              </p>
                            </div>
                          </div>
                        </div>

                        {/* Additional Reason evidence list */}
                        {t.reasons && t.reasons.length > 0 && (
                          <div className="mt-4 pt-4 border-t border-border/40">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                              Detections / Evidence
                            </p>
                            <ul className="space-y-1.5">
                              {t.reasons.map((r, rIdx) => {
                                const isThreat = t.risk === "DANGEROUS" || t.risk === "SUSPICIOUS";
                                const Icon = isThreat ? AlertTriangle : ShieldCheck;
                                const iconCls = isThreat
                                  ? "text-cyber-danger"
                                  : "text-cyber-success";
                                return (
                                  <li
                                    key={rIdx}
                                    className="text-xs flex items-start gap-2 text-foreground/90"
                                  >
                                    <Icon className={`h-3.5 w-3.5 shrink-0 mt-0.5 ${iconCls}`} />
                                    <span>{r}</span>
                                  </li>
                                );
                              })}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </main>
    </>
  );
}
