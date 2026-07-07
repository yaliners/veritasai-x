import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useThreats, useExtensionInstalled } from "@/lib/veritas/store";
import { EmptyState } from "@/components/veritas/empty-state";
import {
  FileText,
  Shield,
  AlertOctagon,
  TrendingUp,
  Calendar,
  Clock,
  Award,
  Printer,
  CheckCircle,
} from "lucide-react";
import type { ThreatRecord } from "@/lib/veritas/types";

export const Route = createFileRoute("/report")({
  head: () => ({
    meta: [
      { title: "Weekly Security Report — VeritasShield AI" },
      {
        name: "description",
        content: "Weekly threat summary, security score analysis, and personalized insights.",
      },
    ],
  }),
  component: SecurityReport,
});

function SecurityReport() {
  const [threats] = useThreats();
  const isExtensionInstalled = useExtensionInstalled();

  const reportData = useMemo(() => {
    const now = Date.now();
    const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;

    // Filter threats from this week
    const weeklyScans = threats.filter((t) => t.timestamp > sevenDaysAgo);

    if (weeklyScans.length === 0) {
      return null;
    }

    const totalScanned = weeklyScans.length;
    const threatsBlocked = weeklyScans.filter((t) => t.risk === "DANGEROUS").length;
    const suspiciousEncountered = weeklyScans.filter((t) => t.risk === "SUSPICIOUS").length;

    // Most dangerous site
    const sortedByScore = [...weeklyScans].sort((a, b) => b.score - a.score);
    const mostDangerousSite = sortedByScore[0]?.score > 35 ? sortedByScore[0] : null;

    // Top threat category (module)
    const categoryCounts: Record<string, number> = {};
    weeklyScans
      .filter((t) => t.risk === "DANGEROUS" || t.risk === "SUSPICIOUS")
      .forEach((t) => {
        categoryCounts[t.module] = (categoryCounts[t.module] || 0) + 1;
      });

    let topThreatCategory = "None";
    let maxCategoryCount = 0;
    Object.entries(categoryCounts).forEach(([cat, count]) => {
      if (count > maxCategoryCount) {
        maxCategoryCount = count;
        topThreatCategory = cat;
      }
    });

    // Security Score = 100 - average threat score
    const avgScore = weeklyScans.reduce((acc, t) => acc + t.score, 0) / totalScanned;
    const securityScore = Math.max(0, Math.min(100, Math.round(100 - avgScore)));

    // Peak threat day and hour
    const dayCounts = Array(7).fill(0);
    const hourCounts = Array(24).fill(0);

    weeklyScans
      .filter((t) => t.risk === "DANGEROUS" || t.risk === "SUSPICIOUS")
      .forEach((t) => {
        const date = new Date(t.timestamp);
        dayCounts[date.getDay()]++;
        hourCounts[date.getHours()]++;
      });

    const daysOfWeek = [
      "Sunday",
      "Monday",
      "Tuesday",
      "Wednesday",
      "Thursday",
      "Friday",
      "Saturday",
    ];
    let peakDayIdx = 0;
    let maxDayCount = -1;
    dayCounts.forEach((count, idx) => {
      if (count > maxDayCount) {
        maxDayCount = count;
        peakDayIdx = idx;
      }
    });

    let peakHour = 0;
    let maxHourCount = -1;
    hourCounts.forEach((count, idx) => {
      if (count > maxHourCount) {
        maxHourCount = count;
        peakHour = idx;
      }
    });

    const peakDay = maxDayCount > 0 ? daysOfWeek[peakDayIdx] : "N/A";
    const peakTimeStr = maxHourCount > 0 ? `${peakHour}:00 - ${peakHour + 1}:00` : "N/A";

    // Recommendations
    const recommendations: string[] = [];
    if (securityScore >= 90) {
      recommendations.push(
        "Your browsing hygiene is outstanding! Keep following the same patterns to stay secure.",
      );
    } else if (securityScore >= 70) {
      recommendations.push(
        "Good safety score, but minor alerts occurred. Be sure to check domains with multiple hyphens or non-standard TLD extensions.",
      );
    } else {
      recommendations.push(
        "Critical security alerts detected. Avoid visiting sites without HTTPS encryption or entering data on freshly-registered domains.",
      );
    }

    if (
      weeklyScans.some((t) =>
        t.reasons.some((r) => r.toLowerCase().includes("http:") || r.toLowerCase().includes("ssl")),
      )
    ) {
      recommendations.push(
        "Warning: Secure Socket Layer (SSL) anomalies detected. Avoid transmitting bank accounts or credit card details on unencrypted HTTP connections.",
      );
    }

    if (
      weeklyScans.some((t) => t.module === "New Domain — High Risk" || t.module === "New Domain")
    ) {
      recommendations.push(
        "Ensure to verify domain addresses for recent registration dates. Scammers frequently buy domains and discard them in under 30 days.",
      );
    }

    if (threatsBlocked > 0) {
      recommendations.push(
        "Our AI engines blocked active phishing threats. We recommend running a full scan of your operating system with a verified antivirus provider.",
      );
    }

    return {
      totalScanned,
      threatsBlocked,
      suspiciousEncountered,
      mostDangerousSite,
      topThreatCategory,
      securityScore,
      peakDay,
      peakTimeStr,
      recommendations,
    };
  }, [threats]);

  const handlePrint = () => {
    window.print();
  };

  return (
    <>
      <div className="print:hidden">
        <Topbar
          title="Weekly Security Report"
          subtitle="Auto-generated intelligence briefing and safety scorecard"
        />
      </div>
      <main className="flex-1 space-y-6 p-4 lg:p-8 print:p-0 print:bg-white print:text-black">
        {!isExtensionInstalled ? (
          <div className="print:hidden">
            <EmptyState isInstalled={isExtensionInstalled} />
          </div>
        ) : !reportData ? (
          <div className="glass rounded-2xl p-12 text-center flex flex-col items-center justify-center">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No report data</h3>
            <p className="text-sm text-muted-foreground max-w-md">
              Not enough data to compile this week's report. Start browsing websites with the
              extension active to build threat statistics.
            </p>
          </div>
        ) : (
          <div className="space-y-6 max-w-5xl mx-auto">
            {/* Top action header */}
            <div className="flex justify-between items-center print:hidden">
              <h2 className="text-lg font-bold tracking-tight">Security Briefing</h2>
              <button
                onClick={handlePrint}
                className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-sm font-semibold text-background transition-transform active:scale-95 hover:shadow-[0_0_12px_rgba(6,182,212,0.3)]"
              >
                <Printer className="h-4 w-4" /> Export Report (PDF)
              </button>
            </div>

            {/* Print Header only visible on physical paper */}
            <div className="hidden print:block mb-8 border-b pb-6 border-slate-300">
              <h1 className="text-3xl font-extrabold">VeritasShield AI</h1>
              <p className="text-sm text-slate-500 uppercase tracking-widest mt-1">
                Weekly Security & Threat Telemetry Briefing
              </p>
              <p className="text-xs text-slate-400 mt-0.5">
                Generated on: {new Date().toLocaleDateString()} at {new Date().toLocaleTimeString()}
              </p>
            </div>

            {/* Core Score Panel */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="glass rounded-2xl p-6 flex flex-col justify-between items-center text-center border-l-4 border-l-cyber-cyan min-h-[220px]">
                <div>
                  <Shield className="h-8 w-8 text-cyber-cyan mb-2 mx-auto" />
                  <h3 className="text-sm font-semibold text-muted-foreground">Safety Scorecard</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">Browsing safety grade</p>
                </div>
                <div className="my-4">
                  <span className="text-5xl md:text-6xl font-extrabold font-mono text-cyber-cyan">
                    {reportData.securityScore}
                  </span>
                  <span className="text-sm text-muted-foreground">/100</span>
                </div>
                <span
                  className={`text-xs px-3 py-1 rounded-full font-bold uppercase ${
                    reportData.securityScore >= 90
                      ? "bg-cyber-success/12 text-cyber-success border border-cyber-success/20"
                      : reportData.securityScore >= 70
                        ? "bg-cyber-warning/12 text-cyber-warning border border-cyber-warning/20"
                        : "bg-cyber-danger/12 text-cyber-danger border border-cyber-danger/20"
                  }`}
                >
                  {reportData.securityScore >= 90
                    ? "Excellent"
                    : reportData.securityScore >= 70
                      ? "Fair"
                      : "At Risk"}
                </span>
              </div>

              {/* Stats Block */}
              <div className="glass rounded-2xl p-6 md:col-span-2 grid grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-card/30 border border-border/40 flex flex-col justify-between">
                  <div>
                    <TrendingUp className="h-4.5 w-4.5 text-cyber-cyan mb-1.5" />
                    <p className="text-xs text-muted-foreground font-semibold">Total Scanned</p>
                  </div>
                  <p className="text-3xl font-extrabold font-mono mt-2 text-foreground">
                    {reportData.totalScanned}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-1">Sites scanned this week</p>
                </div>

                <div className="p-4 rounded-xl bg-card/30 border border-border/40 flex flex-col justify-between">
                  <div>
                    <AlertOctagon className="h-4.5 w-4.5 text-cyber-danger mb-1.5" />
                    <p className="text-xs text-muted-foreground font-semibold">Threats Prevented</p>
                  </div>
                  <p className="text-3xl font-extrabold font-mono mt-2 text-cyber-danger">
                    {reportData.threatsBlocked}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-1">Active blocks executed</p>
                </div>

                <div className="p-4 rounded-xl bg-card/30 border border-border/40 flex flex-col justify-between">
                  <div>
                    <Calendar className="h-4.5 w-4.5 text-cyber-warning mb-1.5" />
                    <p className="text-xs text-muted-foreground font-semibold">Peak Threat Day</p>
                  </div>
                  <p className="text-xl font-extrabold mt-2 text-foreground truncate">
                    {reportData.peakDay}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-1">Highest scan volume day</p>
                </div>

                <div className="p-4 rounded-xl bg-card/30 border border-border/40 flex flex-col justify-between">
                  <div>
                    <Clock className="h-4.5 w-4.5 text-primary mb-1.5" />
                    <p className="text-xs text-muted-foreground font-semibold">Peak Threat Hour</p>
                  </div>
                  <p className="text-base font-extrabold mt-2 text-foreground truncate">
                    {reportData.peakTimeStr}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-1">
                    Highest threat score block
                  </p>
                </div>
              </div>
            </div>

            {/* Forensics analysis */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="glass rounded-2xl p-6 space-y-4">
                <h3 className="text-base font-semibold border-b border-border/40 pb-2">
                  Threat Vector Summary
                </h3>
                <div className="space-y-3.5">
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-muted-foreground">Top Threat Category:</span>
                    <span className="font-semibold text-cyber-warning">
                      {reportData.topThreatCategory}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-muted-foreground">Suspicious Domains Encountered:</span>
                    <span className="font-semibold text-foreground">
                      {reportData.suspiciousEncountered}
                    </span>
                  </div>
                  <div className="flex justify-between items-start text-sm">
                    <span className="text-muted-foreground">Most Critical Event:</span>
                    <div className="text-right">
                      {reportData.mostDangerousSite ? (
                        <>
                          <p className="font-mono text-xs font-semibold text-cyber-danger truncate max-w-[200px]">
                            {reportData.mostDangerousSite.domain}
                          </p>
                          <p className="text-[10px] text-muted-foreground">
                            Score: {reportData.mostDangerousSite.score} (
                            {reportData.mostDangerousSite.module})
                          </p>
                        </>
                      ) : (
                        <span className="text-cyber-success font-semibold">None (100% Safe)</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Personalized recommendations */}
              <div className="glass rounded-2xl p-6 space-y-4">
                <h3 className="text-base font-semibold border-b border-border/40 pb-2 flex items-center gap-2">
                  <Award className="h-4.5 w-4.5 text-cyber-cyan" /> AI Remediation Guide
                </h3>
                <ul className="space-y-3">
                  {reportData.recommendations.map((rec, idx) => (
                    <li
                      key={idx}
                      className="text-xs flex gap-2.5 text-foreground/90 leading-relaxed"
                    >
                      <CheckCircle className="h-4 w-4 text-cyber-cyan shrink-0 mt-0.5" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Print Footer only visible on PDF/paper */}
            <div className="hidden print:block text-center text-xs text-slate-400 mt-16 pt-8 border-t border-slate-200">
              VeritasShield AI Cyber SOC System © 2026. Confidential Security Briefing.
            </div>
          </div>
        )}
      </main>
    </>
  );
}
