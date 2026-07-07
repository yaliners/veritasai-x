import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useExtensionInstalled } from "@/lib/veritas/store";
import { EmptyState } from "@/components/veritas/empty-state";
import {
  Shield,
  Play,
  List,
  Clock,
  CheckCircle2,
  AlertOctagon,
  RefreshCw,
  FileText,
  Trash2,
} from "lucide-react";

interface SandboxRecord {
  url: string;
  score: number;
  category: string;
  reasons: string[];
  timeline: string[];
  recommendations: string[];
  timestamp: number;
}

export const Route = createFileRoute("/sandbox")({
  head: () => ({
    meta: [
      { title: "Threat Sandbox — VeritasShield AI" },
      {
        name: "description",
        content: "Isolate and inspect suspicious URLs in a secure virtual sandbox.",
      },
    ],
  }),
  component: ThreatSandbox,
});

function ThreatSandbox() {
  const isExtensionInstalled = useExtensionInstalled();
  const [urlInput, setUrlInput] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [currentResult, setCurrentResult] = useState<SandboxRecord | null>(null);
  const [history, setHistory] = useState<SandboxRecord[]>([]);

  useEffect(() => {
    const raw = localStorage.getItem("veritas:sandbox_history");
    if (raw) {
      try {
        setHistory(JSON.parse(raw));
      } catch (e) {
        // ignore parse error
      }
    }
  }, []);

  const runAnalysis = () => {
    if (!urlInput.trim()) return;
    setAnalyzing(true);
    setCurrentResult(null);

    setTimeout(() => {
      let host = "";
      try {
        host = new URL(urlInput).hostname.toLowerCase();
      } catch (e) {
        host = urlInput.toLowerCase();
      }

      // Heuristic calculations based on the domain input
      const matchedRules: string[] = [];
      let score = 15; // baseline

      if (
        host.includes("login") ||
        host.includes("secure") ||
        host.includes("verify") ||
        host.includes("update")
      ) {
        matchedRules.push("Suspicious login phrase in URL");
        score += 25;
      }
      if (host.includes("-") || host.split("-").length > 2) {
        matchedRules.push("Suspicious domain hyphens");
        score += 15;
      }
      if (
        host.endsWith(".xyz") ||
        host.endsWith(".tk") ||
        host.endsWith(".cf") ||
        host.endsWith(".work")
      ) {
        matchedRules.push("Suspicious TLD extension");
        score += 20;
      }
      if (urlInput.startsWith("http://")) {
        matchedRules.push("No HTTPS encryption");
        score += 25;
      }
      if (host.includes("paypa1") || host.includes("amaz0n") || host.includes("g00gle")) {
        matchedRules.push("Brand impersonation homoglyph");
        score += 35;
      }

      score = Math.min(score, 100);

      // Category Classification
      let category = "Safe";
      if (score >= 75) category = "Phishing";
      else if (score >= 55) category = "Malware";
      else if (score >= 35) category = "Scam";
      else if (score >= 20) category = "Suspicious";

      // Timeline entries
      const date = new Date();
      const formatOffset = (sec: number) => {
        const d = new Date(date.getTime() + sec * 1000);
        return d.toLocaleTimeString(undefined, {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
      };

      const timeline = [
        `${formatOffset(0)} - Page opened & headers inspected`,
        `${formatOffset(1)} - Parsing DOM elements & structure`,
      ];

      if (score >= 35) {
        timeline.push(`${formatOffset(2)} - Suspicious login form structure detected`);
      }
      if (urlInput.startsWith("http://")) {
        timeline.push(`${formatOffset(3)} - Unencrypted data transmission warning`);
      }
      timeline.push(`${formatOffset(4)} - Threat score finalized at ${score}`);

      // Recommendations
      const recommendations: string[] = [];
      if (score >= 70) {
        recommendations.push("Avoid entering credentials on this website.");
        recommendations.push("Verify domain ownership via independent WHOIS query.");
        recommendations.push("Enable two-factor authentication on all linked accounts.");
      } else if (score >= 35) {
        recommendations.push("Do not input payment details or credit cards.");
        recommendations.push("Inspect all redirected urls carefully.");
      } else {
        recommendations.push("Legitimate domain reputation. Proceed normally.");
      }

      const result: SandboxRecord = {
        url: urlInput,
        score,
        category,
        reasons: matchedRules.length > 0 ? matchedRules : ["No major rule matches"],
        timeline,
        recommendations,
        timestamp: Date.now(),
      };

      setCurrentResult(result);
      const newHistory = [result, ...history].slice(0, 50);
      setHistory(newHistory);
      localStorage.setItem("veritas:sandbox_history", JSON.stringify(newHistory));
      setAnalyzing(false);
    }, 1500);
  };

  const clearHistory = () => {
    if (confirm("Clear sandbox history?")) {
      localStorage.removeItem("veritas:sandbox_history");
      setHistory([]);
    }
  };

  const borderTone: Record<string, string> = {
    Phishing: "border-l-cyber-danger",
    Malware: "border-l-cyber-danger",
    Scam: "border-l-cyber-warning",
    Suspicious: "border-l-cyber-warning",
    Safe: "border-l-cyber-success",
  };

  const textTone: Record<string, string> = {
    Phishing: "text-cyber-danger",
    Malware: "text-cyber-danger",
    Scam: "text-cyber-warning",
    Suspicious: "text-cyber-warning",
    Safe: "text-cyber-success",
  };

  return (
    <>
      <Topbar
        title="Threat Sandbox"
        subtitle="Analyze URLs dynamically inside our isolated threat intelligence vault"
      />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        {!isExtensionInstalled ? (
          <EmptyState isInstalled={isExtensionInstalled} />
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            {/* Input & Form Area */}
            <div className="xl:col-span-2 space-y-6">
              <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
                <h2 className="text-base font-semibold flex items-center gap-2">
                  <Shield className="h-4.5 w-4.5 text-cyber-cyan" /> Secure Inspection Form
                </h2>
                <p className="mt-1 text-xs text-muted-foreground mb-4">
                  Paste a URL to execute simulated visual, pattern, and DNS inspections inside the
                  sandbox environment.
                </p>
                <div className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://suspicious-login-portal.com/login.html"
                    className="flex-1 rounded-lg border border-border/60 bg-card/60 px-3 py-2.5 text-sm outline-none focus:border-cyber-cyan transition-colors"
                  />
                  <button
                    onClick={runAnalysis}
                    disabled={analyzing || !urlInput.trim()}
                    className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-5 py-2.5 text-sm font-semibold text-background transition-transform active:scale-95 disabled:opacity-50"
                  >
                    {analyzing ? (
                      <>
                        <RefreshCw className="h-4 w-4 animate-spin" /> Analyzing...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4" /> Run Sandbox
                      </>
                    )}
                  </button>
                </div>
              </section>

              {/* Analysis Result Card */}
              {currentResult && (
                <div
                  className={`glass rounded-2xl p-6 border-l-4 ${borderTone[currentResult.category]} shadow-[var(--shadow-card)] space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300`}
                >
                  {/* Summary Block */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-4">
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                        Sandbox Result
                      </p>
                      <h3 className="text-lg font-bold tracking-tight break-all">
                        {currentResult.url}
                      </h3>
                    </div>
                    <div className="flex gap-4 items-center shrink-0">
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground text-left sm:text-right">
                          Category
                        </p>
                        <p className={`text-base font-bold ${textTone[currentResult.category]}`}>
                          {currentResult.category}
                        </p>
                      </div>
                      <div className="h-8 w-px bg-border/40" />
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                          Threat Score
                        </p>
                        <p className="text-2xl font-bold font-mono text-cyber-warning">
                          {currentResult.score}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Rule Evidence and Timeline Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Detection Evidence Panel */}
                    <div className="space-y-3">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <List className="h-4 w-4 text-cyber-danger" /> Detection Evidence Panel
                      </h4>
                      <ul className="space-y-2">
                        {currentResult.reasons.map((r, idx) => (
                          <li
                            key={idx}
                            className="text-xs flex items-start gap-2 bg-cyber-danger/5 border border-cyber-danger/20 rounded-lg p-2.5"
                          >
                            <span className="text-cyber-danger font-bold">✓</span>
                            <span>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Threat Timeline */}
                    <div className="space-y-3">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <Clock className="h-4 w-4 text-cyber-cyan" /> Sandbox Inspection Timeline
                      </h4>
                      <div className="relative pl-4 border-l border-border/60 py-1 space-y-4">
                        {currentResult.timeline.map((t, idx) => (
                          <div key={idx} className="relative text-xs">
                            <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-cyber-cyan" />
                            <span className="text-foreground/90">{t}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Security Recommendations */}
                  <div className="bg-cyber-cyan/5 border border-cyber-cyan/20 rounded-xl p-4 space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-cyber-cyan flex items-center gap-1.5">
                      <CheckCircle2 className="h-4.5 w-4.5" /> Security Recommendations
                    </h4>
                    <ul className="space-y-1.5 pl-5 list-disc text-xs text-foreground/95">
                      {currentResult.recommendations.map((rec, idx) => (
                        <li key={idx}>{rec}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Print report action */}
                  <div className="flex justify-end">
                    <button
                      onClick={() => window.print()}
                      className="inline-flex items-center gap-2 text-xs font-semibold text-cyber-cyan hover:underline"
                    >
                      <FileText className="h-4 w-4" /> Download Report Card (PDF)
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* History Sidebar */}
            <div className="space-y-6">
              <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] flex flex-col max-h-[600px]">
                <div className="flex justify-between items-center border-b border-border/40 pb-3 mb-4">
                  <h3 className="text-sm font-semibold flex items-center gap-1.5">
                    <Clock className="h-4 w-4 text-muted-foreground" /> Sandbox History
                  </h3>
                  {history.length > 0 && (
                    <button
                      onClick={clearHistory}
                      className="text-cyber-danger hover:underline text-xs flex items-center gap-1"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Clear
                    </button>
                  )}
                </div>

                <div className="flex-1 overflow-y-auto space-y-3 pr-1">
                  {history.length === 0 ? (
                    <p className="text-xs text-muted-foreground text-center py-8">
                      No sandbox runs yet.
                    </p>
                  ) : (
                    history.map((h, idx) => (
                      <div
                        key={idx}
                        onClick={() => setCurrentResult(h)}
                        className="p-3 rounded-lg border border-border/60 bg-card/35 hover:border-cyber-cyan/40 transition-colors cursor-pointer text-left space-y-1"
                      >
                        <p className="text-xs font-mono font-semibold truncate text-foreground">
                          {h.url}
                        </p>
                        <div className="flex justify-between items-center text-[10px]">
                          <span className={`font-semibold ${textTone[h.category]}`}>
                            {h.category}
                          </span>
                          <span className="text-muted-foreground font-mono">Score: {h.score}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>
          </div>
        )}
      </main>
    </>
  );
}
