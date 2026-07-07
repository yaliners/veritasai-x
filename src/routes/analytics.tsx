import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { StatCard } from "@/components/veritas/stat-card";
import { EmptyState } from "@/components/veritas/empty-state";
import { useExtensionInstalled } from "@/lib/veritas/store";
import { useVeritasScans } from "@/hooks/useVeritasScans";
import { ShieldCheck, ShieldAlert, ShieldX, Shield, Brain, TrendingUp } from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from "recharts";

export const Route = createFileRoute("/analytics")({
  head: () => ({
    meta: [
      { title: "Analytics — VeritasShield AI" },
      {
        name: "description",
        content: "AI-driven threat analytics, distributions, and trust trends.",
      },
    ],
  }),
  component: AnalyticsCenter,
});

const COLORS = [
  "oklch(0.65 0.24 27)",
  "oklch(0.78 0.16 75)",
  "oklch(0.72 0.18 145)",
  "oklch(0.82 0.16 220)",
  "oklch(0.65 0.2 295)",
];

function AnalyticsCenter() {
  const { scans: threats, stats } = useVeritasScans();
  const isExtensionInstalled = useExtensionInstalled();

  const counts = useMemo(() => {
    const c = { DANGEROUS: 0, SUSPICIOUS: 0, SAFE: 0, TRUSTED: 0 };
    threats.forEach((t) => {
      if (
        t.risk === "DANGEROUS" ||
        t.risk === "SUSPICIOUS" ||
        t.risk === "SAFE" ||
        t.risk === "TRUSTED"
      ) {
        c[t.risk]++;
      }
    });
    return c;
  }, [threats]);

  const total = threats.length;
  const avgThreat = total > 0 ? Math.round(threats.reduce((s, t) => s + t.score, 0) / total) : 0;
  const avgTrust =
    total > 0 ? Math.round(threats.reduce((s, t) => s + t.trustScore, 0) / total) : 0;
  const aiConf = total > 0 ? Math.round(threats.reduce((s, t) => s + t.confidence, 0) / total) : 0;

  const riskData = [
    { name: "Dangerous", value: counts.DANGEROUS },
    { name: "Suspicious", value: counts.SUSPICIOUS },
    { name: "Safe", value: counts.SAFE },
    { name: "Trusted", value: counts.TRUSTED },
  ];

  const moduleData = useMemo(() => {
    const m: Record<string, number> = {};
    threats.forEach((t) => {
      m[t.module] = (m[t.module] || 0) + 1;
    });
    return Object.entries(m).map(([name, value]) => ({ name, value }));
  }, [threats]);

  const trendData = useMemo(() => {
    return Array.from({ length: 14 }).map((_, i) => {
      const dayStart = (14 - i - 1) * 86400000;
      const dayEnd = (14 - i) * 86400000;
      const now = Date.now();
      const threatsInDay = threats.filter((t) => {
        const age = now - t.timestamp;
        return age >= dayStart && age < dayEnd;
      }).length;
      const avgScoreInDay =
        threats
          .filter((t) => {
            const age = now - t.timestamp;
            return age >= dayStart && age < dayEnd;
          })
          .reduce((s, t) => s + t.score, 0) || 0;
      const threatScoreInDay = threatsInDay > 0 ? Math.round(avgScoreInDay / threatsInDay) : 0;
      const avgTrustInDay =
        threats
          .filter((t) => {
            const age = now - t.timestamp;
            return age >= dayStart && age < dayEnd;
          })
          .reduce((s, t) => s + t.trustScore, 0) || 0;
      const trustScoreInDay = threatsInDay > 0 ? Math.round(avgTrustInDay / threatsInDay) : 0;
      return {
        day: `D${i + 1}`,
        threat: threatScoreInDay,
        trust: trustScoreInDay,
      };
    });
  }, [threats]);

  const topCategory = useMemo(() => {
    const sorted = [...moduleData].sort((a, b) => b.value - a.value);
    return sorted[0]?.name ?? "—";
  }, [moduleData]);

  return (
    <>
      <Topbar title="Analytics Center" subtitle="AI-augmented detection intelligence" />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        {threats.length === 0 || !isExtensionInstalled ? (
          <EmptyState isInstalled={isExtensionInstalled} />
        ) : (
          <>
            <section className="grid grid-cols-1 min-[480px]:grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Total Scans" value={total} icon={Shield} accent="cyan" />
              <StatCard label="Dangerous" value={counts.DANGEROUS} icon={ShieldX} accent="danger" />
              <StatCard
                label="Suspicious"
                value={counts.SUSPICIOUS}
                icon={ShieldAlert}
                accent="warning"
              />
              <StatCard
                label="Safe + Trusted"
                value={counts.SAFE + counts.TRUSTED}
                icon={ShieldCheck}
                accent="success"
              />
            </section>

            <section className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <div className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
                <h2 className="text-base font-semibold">Risk Distribution</h2>
                <p className="mb-4 text-xs text-muted-foreground">Across the threat database</p>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={riskData}
                        dataKey="value"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={4}
                        stroke="none"
                      >
                        {riskData.map((_, i) => (
                          <Cell key={i} fill={COLORS[i]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "oklch(0.18 0.04 265)",
                          border: "1px solid oklch(0.3 0.04 260)",
                          borderRadius: 12,
                          fontSize: 12,
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="glass rounded-2xl p-6 xl:col-span-2 shadow-[var(--shadow-card)]">
                <h2 className="text-base font-semibold">Threat & Trust Trend</h2>
                <p className="mb-4 text-xs text-muted-foreground">14-day rolling intelligence</p>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.35 0.04 260 / 30%)" />
                      <XAxis dataKey="day" stroke="oklch(0.7 0.03 250)" fontSize={11} />
                      <YAxis stroke="oklch(0.7 0.03 250)" fontSize={11} />
                      <Tooltip
                        contentStyle={{
                          background: "oklch(0.18 0.04 265)",
                          border: "1px solid oklch(0.3 0.04 260)",
                          borderRadius: 12,
                          fontSize: 12,
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                      <Line
                        type="monotone"
                        dataKey="threat"
                        stroke="oklch(0.65 0.24 27)"
                        strokeWidth={2}
                        dot={false}
                      />
                      <Line
                        type="monotone"
                        dataKey="trust"
                        stroke="oklch(0.82 0.16 220)"
                        strokeWidth={2}
                        dot={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </section>

            <section className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <div className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
                <h2 className="text-base font-semibold">Module Distribution</h2>
                <p className="mb-4 text-xs text-muted-foreground">Detections per engine</p>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={moduleData} dataKey="value" outerRadius={90} stroke="none">
                        {moduleData.map((_, i) => (
                          <Cell key={i} fill={COLORS[i % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "oklch(0.18 0.04 265)",
                          border: "1px solid oklch(0.3 0.04 260)",
                          borderRadius: 12,
                          fontSize: 12,
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
                <h2 className="text-base font-semibold">User Feedback & Accuracy</h2>
                <p className="mb-4 text-xs text-muted-foreground">
                  Reputation verification telemetry
                </p>
                <div className="space-y-4">
                  <div className="flex justify-between items-center border-b border-border/30 pb-2">
                    <span className="text-xs text-muted-foreground">Confirmed Threats</span>
                    <span className="text-xs font-semibold text-cyber-success">
                      {stats.confirmed}
                    </span>
                  </div>
                  <div className="flex justify-between items-center border-b border-border/30 pb-2">
                    <span className="text-xs text-muted-foreground">False Positives</span>
                    <span className="text-xs font-semibold text-cyber-danger">
                      {stats.falsePositives}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">Estimated Accuracy</span>
                    <span className="text-xs font-bold text-cyber-cyan">{stats.accuracy}%</span>
                  </div>
                </div>
              </div>

              <div className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] grid grid-cols-2 gap-4">
                <Insight
                  label="Average Threat Score"
                  value={avgThreat}
                  tone="text-cyber-danger"
                  icon={ShieldAlert}
                />
                <Insight
                  label="Average Trust Score"
                  value={avgTrust}
                  tone="text-cyber-success"
                  icon={ShieldCheck}
                />
                <Insight
                  label="AI Confidence"
                  value={`${aiConf}%`}
                  tone="text-cyber-cyan"
                  icon={Brain}
                />
                <Insight
                  label="Top Threat Category"
                  value={topCategory}
                  tone="text-cyber-warning"
                  icon={TrendingUp}
                  small
                />
              </div>
            </section>
          </>
        )}
      </main>
    </>
  );
}

function Insight({
  label,
  value,
  tone,
  icon: Icon,
  small,
}: {
  label: string;
  value: string | number;
  tone: string;
  icon: React.ElementType;
  small?: boolean;
}) {
  return (
    <div className="rounded-xl border border-border/60 bg-card/40 p-5">
      <div className="mb-2 flex items-center justify-between text-muted-foreground">
        <p className="text-[10px] uppercase tracking-[0.18em]">{label}</p>
        <Icon className="h-4 w-4" />
      </div>
      <p className={`mono font-bold ${tone} ${small ? "text-lg" : "text-3xl"}`}>{value}</p>
    </div>
  );
}
