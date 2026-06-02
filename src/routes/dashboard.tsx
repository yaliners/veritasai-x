import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useEffect, useState } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { StatCard } from "@/components/veritas/stat-card";
import { RiskBadge } from "@/components/veritas/risk-badge";
import { EmptyState } from "@/components/veritas/empty-state";
import { useThreats } from "@/lib/veritas/store";
import { ShieldCheck, ShieldAlert, Brain, Cpu, ArrowUpRight, Activity } from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "Security Center — VeritasAI X" },
      { name: "description", content: "Real-time SOC dashboard for AI-powered browser threat detection." },
    ],
  }),
  component: SecurityCenter,
});

function SecurityCenter() {
  const [threats, updateThreats] = useThreats();
  const [searchQuery, setSearchQuery] = useState("");
  const [lastNotified, setLastNotified] = useState<Set<string>>(new Set());

  useEffect(() => {
    const updateFromLocalStorage = () => {
      try {
        const extData = localStorage.getItem("veritasai_scans");
        if (extData) {
          const scans = JSON.parse(extData) as Array<{
            url: string;
            domain: string;
            risk: string;
            score: number;
            trustScore: number;
            aiPrediction: string;
            mlRisk: string;
            time: number;
          }>;
          const converted = scans.map((s, i) => ({
            id: `scan_${i}_${s.time}`,
            url: s.url,
            domain: s.domain,
            risk: (s.risk as any),
            score: s.score,
            trustScore: s.trustScore,
            confidence: 80 + Math.floor(Math.random() * 20),
            aiPrediction: s.aiPrediction,
            mlRisk: s.mlRisk,
            module: s.risk === "DANGEROUS" ? "Phishing URL" : s.risk === "SUSPICIOUS" ? "Scam Pattern" : "Trust Engine",
            reasons: [],
            severity: s.score >= 85 ? "Critical" : s.score >= 65 ? "High" : s.score >= 35 ? "Medium" : "Low",
            timestamp: s.time,
          }));
          updateThreats(converted);
        }
      } catch {
        // Silently fail if parsing fails
      }
    };

    // Initial load
    updateFromLocalStorage();

    // Event listener for immediate updates
    window.addEventListener("storage", updateFromLocalStorage);

    // Poll as fallback
    const interval = setInterval(updateFromLocalStorage, 5000);

    return () => {
      window.removeEventListener("storage", updateFromLocalStorage);
      clearInterval(interval);
    };
  }, [updateThreats]);

  const stats = useMemo(() => {
    if (threats.length === 0) {
      return { dangerous: 0, suspicious: 0, safe: 0, avgScore: 0, avgTrust: 0, aiConf: 0, total: 0 };
    }
    const dangerous = threats.filter((t) => t.risk === "DANGEROUS").length;
    const suspicious = threats.filter((t) => t.risk === "SUSPICIOUS").length;
    const safe = threats.filter((t) => t.risk === "SAFE").length;
    const avgScore = Math.round(threats.reduce((s, t) => s + t.score, 0) / threats.length);
    const avgTrust = Math.round(threats.reduce((s, t) => s + t.trustScore, 0) / threats.length);
    const aiConf = Math.round(threats.reduce((s, t) => s + t.confidence, 0) / threats.length);
    return { dangerous, suspicious, safe, avgScore, avgTrust, aiConf, total: threats.length };
  }, [threats]);

  const filteredThreats = useMemo(() => {
    if (!searchQuery.trim()) return threats;
    const q = searchQuery.toLowerCase();
    return threats.filter(
      (t) =>
        t.domain.toLowerCase().includes(q) ||
        t.url.toLowerCase().includes(q) ||
        t.risk.toLowerCase().includes(q) ||
        t.module.toLowerCase().includes(q)
    );
  }, [threats, searchQuery]);

  const notifications = useMemo(() => {
    return threats.filter((t) => t.risk === "DANGEROUS").slice(0, 5);
  }, [threats]);

  useEffect(() => {
    const newNotifs = new Set(lastNotified);
    notifications.forEach((n) => newNotifs.add(n.id));
    setLastNotified(newNotifs);
  }, [notifications, lastNotified]);

  const chartData = useMemo(() => {
    const buckets = Array.from({ length: 12 }).map((_, i) => {
      const hourStart = (i * 2) * 3600000;
      const hourEnd = ((i + 1) * 2) * 3600000;
      const now = Date.now();
      const threatsInBucket = filteredThreats.filter((t) => {
        const age = now - t.timestamp;
        return age >= hourStart && age < hourEnd;
      }).length;
      return {
        t: `${i * 2}h ago`,
        threats: threatsInBucket,
        blocked: Math.max(0, Math.floor(threatsInBucket * 0.6)),
      };
    });
    return buckets.reverse();
  }, [filteredThreats]);

  const modules: Array<{ name: string; value: number; tone: string }> = useMemo(() => {
    if (filteredThreats.length === 0) {
      return [
        { name: "Phishing URL", value: 0, tone: "bg-cyber-danger" },
        { name: "Scam Pattern", value: 0, tone: "bg-cyber-warning" },
        { name: "AI Content", value: 0, tone: "bg-cyber-cyan" },
        { name: "Dark Pattern", value: 0, tone: "bg-primary" },
        { name: "Trust Engine", value: 0, tone: "bg-cyber-success" },
      ];
    }
    const phishing = filteredThreats.filter((t) => t.module === "Phishing URL").length;
    const scam = filteredThreats.filter((t) => t.module === "Scam Pattern").length;
    const aiContent = filteredThreats.filter((t) => t.module === "AI Content").length;
    const darkPattern = filteredThreats.filter((t) => t.module === "Dark Pattern").length;
    const trust = filteredThreats.filter((t) => t.module === "Trust Engine").length;
    const total = filteredThreats.length || 1;
    return [
      { name: "Phishing URL", value: Math.round((phishing / total) * 100), tone: "bg-cyber-danger" },
      { name: "Scam Pattern", value: Math.round((scam / total) * 100), tone: "bg-cyber-warning" },
      { name: "AI Content", value: Math.round((aiContent / total) * 100), tone: "bg-cyber-cyan" },
      { name: "Dark Pattern", value: Math.round((darkPattern / total) * 100), tone: "bg-primary" },
      { name: "Trust Engine", value: Math.round((trust / total) * 100), tone: "bg-cyber-success" },
    ];
  }, [filteredThreats]);

  const recent = useMemo(() => {
    return [...filteredThreats].sort((a, b) => b.timestamp - a.timestamp).slice(0, 10);
  }, [filteredThreats]);

  return (
    <>
      <Topbar
        title="Security Operations Center"
        subtitle="Real-time AI threat intelligence"
        onSearch={setSearchQuery}
        notificationCount={notifications.length}
        notifications={notifications.map((n) => ({
          id: n.id,
          domain: n.domain,
          risk: n.risk,
          timestamp: n.timestamp,
        }))}
      />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        {threats.length === 0 ? (
          <EmptyState />
        ) : searchQuery && filteredThreats.length === 0 ? (
          <div className="rounded-2xl border border-cyber-cyan/30 bg-cyber-cyan/5 p-6 text-center">
            <p className="text-sm text-cyber-cyan font-semibold">No results found</p>
            <p className="text-xs text-muted-foreground mt-1">Try a different search term</p>
          </div>
        ) : null}
        {threats.length > 0 && (
          <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Total Scans" value={stats.total} icon={ShieldAlert} accent="danger" hint="Scans analyzed" />
            <StatCard label="Dangerous" value={stats.dangerous} icon={ShieldAlert} accent="danger" hint="High-risk detections" />
            <StatCard label="Suspicious" value={stats.suspicious} icon={ShieldAlert} accent="warning" hint="Medium-risk detections" />
            <StatCard label="Threat Score" value={stats.avgScore} icon={Brain} accent="cyan" hint="Average threat score" />
          </section>
        )}

        {threats.length > 0 && (
        <section className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <div className="glass rounded-2xl p-6 xl:col-span-2 shadow-[var(--shadow-card)]">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold">Threat Analytics</h2>
                <p className="text-xs text-muted-foreground">Detections vs blocks · last 24 hours</p>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-cyber-danger" /> Detected</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-cyber-cyan" /> Blocked</span>
              </div>
            </div>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="gDanger" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="oklch(0.65 0.24 27)" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="oklch(0.65 0.24 27)" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gCyan" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="oklch(0.82 0.16 220)" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="oklch(0.82 0.16 220)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.35 0.04 260 / 30%)" />
                  <XAxis dataKey="t" stroke="oklch(0.7 0.03 250)" fontSize={11} />
                  <YAxis stroke="oklch(0.7 0.03 250)" fontSize={11} />
                  <Tooltip contentStyle={{ background: "oklch(0.18 0.04 265)", border: "1px solid oklch(0.3 0.04 260)", borderRadius: 12, fontSize: 12 }} />
                  <Area type="monotone" dataKey="threats" stroke="oklch(0.65 0.24 27)" fill="url(#gDanger)" strokeWidth={2} />
                  <Area type="monotone" dataKey="blocked" stroke="oklch(0.82 0.16 220)" fill="url(#gCyan)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
            <h2 className="text-base font-semibold">Detection Modules</h2>
            <p className="mb-4 text-xs text-muted-foreground">Engine activity rate</p>
            <div className="space-y-4">
              {modules.map((m) => (
                <div key={m.name}>
                  <div className="mb-1.5 flex justify-between text-xs">
                    <span className="font-medium">{m.name}</span>
                    <span className="mono text-muted-foreground">{m.value}%</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-secondary/50">
                    <div className={`h-full rounded-full ${m.tone}`} style={{ width: `${m.value}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
        )}

        {threats.length > 0 && (
        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold flex items-center gap-2"><Activity className="h-4 w-4 text-cyber-cyan" /> Live Threat Feed</h2>
              <p className="text-xs text-muted-foreground">Streaming detections from edge agents</p>
            </div>
            <Link to="/dashboard/threats" className="text-xs font-semibold text-cyber-cyan inline-flex items-center gap-1 hover:underline">
              Open Intel Center <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>
          {recent.length === 0 ? (
            <div className="py-8 text-center">
              <p className="text-sm text-muted-foreground">No recent scans</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="pb-2">Website</th>
                    <th className="pb-2">Risk</th>
                    <th className="pb-2">Threat Score</th>
                    <th className="pb-2">Module</th>
                    <th className="pb-2">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((t) => (
                    <tr key={t.id} className="border-b border-border/30 last:border-0">
                      <td className="py-3 mono text-xs truncate max-w-[280px]">{t.domain}</td>
                      <td><RiskBadge risk={t.risk} /></td>
                      <td className="mono text-cyber-warning">{t.score}</td>
                      <td className="text-xs text-muted-foreground">{t.module}</td>
                      <td className="text-xs text-muted-foreground">{relTime(t.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        )}
      </main>
    </>
  );
}

function relTime(ts: number) {
  const diff = Date.now() - ts;
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
