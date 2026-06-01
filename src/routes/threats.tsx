import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { RiskBadge } from "@/components/veritas/risk-badge";
import { EmptyState } from "@/components/veritas/empty-state";
import { useThreats, exportThreatsCSV, downloadCSV } from "@/lib/veritas/store";
import { Search, Download, X, Brain, KeyRound, AlertTriangle, ShieldCheck, ChevronDown } from "lucide-react";
import type { ThreatRecord, Risk } from "@/lib/veritas/types";

export const Route = createFileRoute("/threats")({
  head: () => ({
    meta: [
      { title: "Threat Intelligence — VeritasAI X" },
      { name: "description", content: "Searchable threat database with explainable AI insights and severity scoring." },
    ],
  }),
  component: ThreatCenter,
});

function generateExplanation(threat: ThreatRecord) {
  const signals: Array<{ text: string; impact: number }> = [];

  if (threat.risk === "DANGEROUS") {
    signals.push(
      { text: "Domain registered 3 days ago", impact: 38 },
      { text: "Password form without SSL", impact: 31 },
      { text: "Keyword match: scam patterns", impact: 22 }
    );
  } else if (threat.risk === "SUSPICIOUS") {
    signals.push(
      { text: "Unusual domain structure detected", impact: 24 },
      { text: "AI-generated content patterns", impact: 18 },
      { text: "Urgency tactics in messaging", impact: 15 }
    );
  } else if (threat.risk === "SAFE") {
    signals.push(
      { text: "Domain age over 5 years", impact: 45 },
      { text: "Valid SSL certificate found", impact: 28 },
      { text: "No malicious indicators detected", impact: 12 }
    );
  } else {
    signals.push(
      { text: "Enterprise reputation verified", impact: 52 },
      { text: "Industry-standard security headers", impact: 35 },
      { text: "Whitelisted domain authority", impact: 18 }
    );
  }

  const actionMap: Record<Risk, string> = {
    DANGEROUS: "Avoid this site. Do not enter credentials or personal information. Consider blocking it.",
    SUSPICIOUS: "Proceed with caution. Verify the domain independently before sharing any data.",
    SAFE: "This appears to be a legitimate site, but always verify URLs carefully.",
    TRUSTED: "This is a trusted domain. You can proceed safely.",
  };

  return {
    signals: signals.slice(0, 3),
    action: actionMap[threat.risk],
  };
}

function ThreatCenter() {
  const [threats] = useThreats();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Risk | "ALL">("ALL");
  const [selected, setSelected] = useState<ThreatRecord | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return threats
      .filter((t) => (filter === "ALL" ? true : t.risk === filter))
      .filter((t) => t.domain.toLowerCase().includes(query.toLowerCase()) || t.module.toLowerCase().includes(query.toLowerCase()))
      .sort((a, b) => b.score - a.score);
  }, [threats, query, filter]);

  const severityCls: Record<ThreatRecord["severity"], string> = {
    Critical: "text-cyber-danger",
    High: "text-cyber-warning",
    Medium: "text-cyber-cyan",
    Low: "text-muted-foreground",
  };

  return (
    <>
      <Topbar title="Threat Intelligence Center" subtitle="Forensic database with XAI explainability" />
      <main className="flex flex-1 gap-6 p-4 lg:p-8">
        {threats.length === 0 ? (
          <div className="glass flex-1 rounded-2xl p-6 shadow-[var(--shadow-card)] flex items-center justify-center">
            <EmptyState />
          </div>
        ) : (
          <div className="glass flex-1 rounded-2xl p-6 shadow-[var(--shadow-card)]">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2 rounded-lg border border-border/60 bg-card/60 px-3 py-1.5">
                  <Search className="h-3.5 w-3.5 text-muted-foreground" />
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search domain or module…" className="w-64 bg-transparent text-xs outline-none placeholder:text-muted-foreground" />
                </div>
                <select value={filter} onChange={(e) => setFilter(e.target.value as Risk | "ALL")} className="rounded-lg border border-border/60 bg-card/60 px-3 py-1.5 text-xs">
                  <option value="ALL">All risk</option>
                  <option value="DANGEROUS">Dangerous</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="SAFE">Safe</option>
                  <option value="TRUSTED">Trusted</option>
                </select>
              </div>
              <button
                onClick={() => downloadCSV("veritas-threats.csv", exportThreatsCSV(filtered))}
                className="inline-flex items-center gap-2 rounded-lg border border-cyber-cyan/40 bg-cyber-cyan/10 px-3 py-1.5 text-xs font-semibold text-cyber-cyan hover:bg-cyber-cyan/20"
              >
                <Download className="h-3.5 w-3.5" /> Export CSV
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="pb-2 w-8"></th>
                    <th className="pb-2">Website</th>
                    <th className="pb-2">Risk</th>
                    <th className="pb-2">Severity</th>
                    <th className="pb-2">Score</th>
                    <th className="pb-2">Trust</th>
                    <th className="pb-2">Module</th>
                    <th className="pb-2">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((t) => (
                    <>
                      <tr key={t.id} className="cursor-pointer border-b border-border/30 transition-colors hover:bg-cyber-cyan/5">
                        <td className="py-3 text-center">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpandedId(expandedId === t.id ? null : t.id);
                            }}
                            className="p-1 hover:bg-secondary rounded"
                          >
                            <ChevronDown
                              className={`h-4 w-4 transition-transform ${expandedId === t.id ? "rotate-180" : ""}`}
                            />
                          </button>
                        </td>
                        <td className="py-3 mono text-xs truncate max-w-[260px]">{t.domain}</td>
                        <td onClick={() => setSelected(t)}><RiskBadge risk={t.risk} /></td>
                        <td onClick={() => setSelected(t)} className={`text-xs font-semibold ${severityCls[t.severity]}`}>{t.severity}</td>
                        <td onClick={() => setSelected(t)} className="mono text-cyber-warning text-xs">{t.score}</td>
                        <td onClick={() => setSelected(t)} className="mono text-cyber-success text-xs">{t.trustScore}</td>
                        <td onClick={() => setSelected(t)} className="text-xs text-muted-foreground">{t.module}</td>
                        <td onClick={() => setSelected(t)} className="text-xs text-muted-foreground">{new Date(t.timestamp).toLocaleTimeString()}</td>
                      </tr>
                      {expandedId === t.id && (
                        <tr className="border-b border-border/30 bg-card/40">
                          <td colSpan={8} className="py-4 px-4">
                            <ExplanationPanel threat={t} onDismiss={() => setExpandedId(null)} />
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                  {filtered.length === 0 && (
                    <tr><td colSpan={8} className="py-10 text-center text-sm text-muted-foreground">No threats match your query.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {selected && (
          <aside className="glass w-96 shrink-0 rounded-2xl p-6 shadow-[var(--shadow-card)]">
            <div className="mb-4 flex items-start justify-between">
              <div>
                <p className="text-[10px] uppercase tracking-[0.2em] text-cyber-cyan">XAI Explainability</p>
                <h3 className="mt-1 text-base font-semibold">Threat Forensics</h3>
              </div>
              <button onClick={() => setSelected(null)} className="rounded-md p-1 text-muted-foreground hover:bg-secondary"><X className="h-4 w-4" /></button>
            </div>
            <div className="mb-4 rounded-xl border border-border/60 bg-card/50 p-4">
              <p className="mono text-xs break-all">{selected.url}</p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <RiskBadge risk={selected.risk} />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{selected.module}</span>
              </div>
            </div>

            <div className="mb-4 grid grid-cols-3 gap-2 text-center">
              <Stat label="Threat" value={selected.score} tone="text-cyber-danger" />
              <Stat label="Trust" value={selected.trustScore} tone="text-cyber-success" />
              <Stat label="AI Conf." value={`${selected.confidence}%`} tone="text-cyber-cyan" />
            </div>

            <div className="space-y-3">
              <Section icon={<Brain className="h-3.5 w-3.5" />} title="AI Prediction">
                <p className="text-xs text-muted-foreground">{selected.aiPrediction} · ML Risk {selected.mlRisk}</p>
              </Section>
              <Section icon={<AlertTriangle className="h-3.5 w-3.5 text-cyber-warning" />} title="Why flagged">
                <ul className="space-y-1.5">
                  {selected.reasons.map((r) => (
                    <li key={r} className="flex items-start gap-2 text-xs text-foreground/90">
                      <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-cyber-cyan" />
                      {r}
                    </li>
                  ))}
                </ul>
              </Section>
              <Section icon={<KeyRound className="h-3.5 w-3.5 text-cyber-danger" />} title="Detected indicators">
                <div className="flex flex-wrap gap-1.5">
                  {["login form", "password field", "external script", "homoglyph"].map((tag) => (
                    <span key={tag} className="rounded-md border border-border/60 bg-card/60 px-2 py-0.5 text-[10px] text-muted-foreground">{tag}</span>
                  ))}
                </div>
              </Section>
              <Section icon={<ShieldCheck className="h-3.5 w-3.5 text-cyber-success" />} title="Trust indicators">
                <p className="text-xs text-muted-foreground">SSL valid · WHOIS aged 14 days · Reputation: low</p>
              </Section>
            </div>
          </aside>
        )}
      </main>
    </>
  );
}

function ExplanationPanel({ threat, onDismiss }: { threat: ThreatRecord; onDismiss: () => void }) {
  const { signals, action } = generateExplanation(threat);

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-cyber-warning" />
          Why was this flagged?
        </h3>
        <div className="space-y-2">
          {signals.map((signal, i) => (
            <div key={i} className="flex items-center justify-between rounded-lg bg-card/50 p-3 border border-border/40">
              <span className="text-xs text-foreground/90">{signal.text}</span>
              <span className="text-xs font-semibold text-cyber-warning ml-2">+{signal.impact}%</span>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 p-4">
        <p className="text-xs font-semibold text-cyber-cyan mb-2">What you should do</p>
        <p className="text-xs text-foreground/80">{action}</p>
      </div>

      <button
        onClick={onDismiss}
        className="w-full px-3 py-2 text-xs font-semibold rounded-lg border border-border/60 bg-card/60 hover:bg-card transition-colors"
      >
        Dismiss
      </button>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string | number; tone: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-card/50 p-2.5">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={`mono mt-1 text-lg font-bold ${tone}`}>{value}</p>
    </div>
  );
}

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border/60 bg-card/40 p-3">
      <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-foreground">{icon} {title}</p>
      {children}
    </div>
  );
}
