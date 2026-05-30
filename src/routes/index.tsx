import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { StatCard } from "@/components/veritas/stat-card";
import { RiskBadge } from "@/components/veritas/risk-badge";
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

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Security Center — VeritasAI X" },
      { name: "description", content: "Real-time SOC dashboard for AI-powered browser threat detection." },
    ],
  }),
  component: SecurityCenter,
});

function SecurityCenter() {
  const [threats] = useThreats();

  const stats = useMemo(() => {
    const dangerous = threats.filter((t) => t.risk === "DANGEROUS").length;
    const suspicious = threats.filter((t) => t.risk === "SUSPICIOUS").length;
    const avgScore = Math.round(threats.reduce((s, t) => s + t.score, 0) / threats.length);
    const avgTrust = Math.round(threats.reduce((s, t) => s + t.trustScore, 0) / threats.length);
    const aiConf = Math.round(threats.reduce((s, t) => s + t.confidence, 0) / threats.length);
    return { dangerous, suspicious, avgScore, avgTrust, aiConf };
  }, [threats]);

  const chartData = useMemo(() => {
    const buckets = Array.from({ length: 12 }).map((_, i) => ({
      t: `${i * 2}h`,
      threats: Math.round(8 + Math.random() * 22 + (i > 6 ? 8 : 0)),
      blocked: Math.round(4 + Math.random() * 14),
    }));
    return buckets;
  }, []);

  const modules: Array<{ name: string; value: number; tone: string }> = [
    { name: "Phishing URL", value: 86, tone: "bg-cyber-danger" },
    { name: "Scam Pattern", value: 74, tone: "bg-cyber-warning" },
    { name: "AI Content", value: 62, tone: "bg-cyber-cyan" },
    { name: "Dark Pattern", value: 48, tone: "bg-primary" },
    { name: "Trust Engine", value: 92, tone: "bg-cyber-success" },
  ];

  const recent = threats.slice(0, 6);

  return (
    <>
      <Topbar title="Security Operations Center" subtitle="Real-time AI threat intelligence" />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Threat Score" value={stats.avgScore} icon={ShieldAlert} accent="danger" hint="Aggregate risk across active sessions" trend="↑ 4.2% vs last 24h" />
          <StatCard label="Trust Score" value={stats.avgTrust} icon={ShieldCheck} accent="success" hint="Mean reputation index" trend="↑ 1.8% stability" />
          <StatCard label="AI Confidence" value={`${stats.aiConf}%`} icon={Brain} accent="cyan" hint="Gemini-class explainability" />
          <StatCard label="ML Confidence" value={`${Math.max(80, stats.aiConf - 3)}%`} icon={Cpu} accent="warning" hint="Ensemble risk classifier" />
        </section>

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

        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold flex items-center gap-2"><Activity className="h-4 w-4 text-cyber-cyan" /> Live Threat Feed</h2>
              <p className="text-xs text-muted-foreground">Streaming detections from edge agents</p>
            </div>
            <Link to="/threats" className="text-xs font-semibold text-cyber-cyan inline-flex items-center gap-1 hover:underline">
              Open Intel Center <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>
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
        </section>
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
