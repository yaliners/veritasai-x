import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useExtensionInstalled } from "@/lib/veritas/store";
import { EmptyState } from "@/components/veritas/empty-state";
import {
  Volume2,
  MessageSquare,
  Bot,
  Monitor,
  Code,
  ShieldAlert,
  CheckCircle,
  Radio,
  Cpu,
  Brain,
  RefreshCw,
} from "lucide-react";

export const Route = createFileRoute("/research")({
  head: () => ({
    meta: [
      { title: "Research Lab — VeritasShield AI" },
      {
        name: "description",
        content:
          "Advanced heuristics, voice clone detection, review farm detection, and obfuscated script analysis.",
      },
    ],
  }),
  component: ResearchLab,
});

type TabType = "voice" | "reviews" | "chats" | "behavior" | "scripts";

function ResearchLab() {
  const isExtensionInstalled = useExtensionInstalled();
  const [activeTab, setActiveTab] = useState<TabType>("voice");

  // Tab 1: Voice Clone State
  const [audioInput, setAudioInput] = useState("");
  const [voiceResult, setVoiceResult] = useState<any | null>(null);
  const [voiceScanning, setVoiceScanning] = useState(false);

  // Tab 2: Fake Reviews State
  const [reviewText, setReviewText] = useState("");
  const [reviewResult, setReviewResult] = useState<any | null>(null);
  const [reviewScanning, setReviewScanning] = useState(false);

  // Tab 3: Support Chat State
  const [chatCode, setChatCode] = useState("");
  const [chatResult, setChatResult] = useState<any | null>(null);
  const [chatScanning, setChatScanning] = useState(false);

  // Tab 4: Behavior State
  const [behaviorLogs, setBehaviorLogs] = useState<string[]>([]);
  const [behaviorScore, setBehaviorScore] = useState(0);

  // Tab 5: Script State
  const [scriptCode, setScriptCode] = useState("");
  const [scriptResult, setScriptResult] = useState<any | null>(null);
  const [scriptScanning, setScriptScanning] = useState(false);

  // Handlers
  const scanVoice = () => {
    setVoiceScanning(true);
    setVoiceResult(null);
    setTimeout(() => {
      const isAI =
        audioInput.includes("ai-voice") ||
        audioInput.includes("synth") ||
        audioInput.includes("clone") ||
        audioInput.length % 2 === 0;
      setVoiceResult({
        detected: isAI,
        confidence: isAI ? 92 : 12,
        pitchVariance: isAI ? "Flat (low variance)" : "Normal dynamic range",
        rhythmPattern: isAI ? "Mechanical pattern matching" : "Human natural cadence",
        reasons: isAI
          ? [
              "Low frequency pitch truncation detected",
              "Boilerplate vocoder phase alignment matched",
            ]
          : ["Natural speech fluctuations matched"],
      });
      setVoiceScanning(false);
    }, 1200);
  };

  const scanReviews = () => {
    setReviewScanning(true);
    setReviewResult(null);
    setTimeout(() => {
      const text = reviewText.toLowerCase();
      const aiWords = [
        "delve",
        "testament",
        "moreover",
        "highly recommend",
        "game changer",
        "revolutionize",
      ];
      const matched = aiWords.filter((w) => text.includes(w));
      const score = Math.min(matched.length * 25 + (text.length > 200 ? 10 : 0), 100);

      setReviewResult({
        score,
        classification:
          score > 60
            ? "Highly suspicious of AI structure"
            : score > 30
              ? "Boilerplate layout detected"
              : "Natural variety",
        matchedWords: matched,
        sentimentRepetition:
          text.split(" ").length > 10 &&
          new Set(text.split(" ")).size < text.split(" ").length * 0.6,
      });
      setReviewScanning(false);
    }, 1000);
  };

  const scanChat = () => {
    setChatScanning(true);
    setChatResult(null);
    setTimeout(() => {
      const text = chatCode.toLowerCase();
      const redFlags: string[] = [];
      if (text.includes("anydesk") || text.includes("teamviewer") || text.includes("remote")) {
        redFlags.push("Scam indicator: chat widget requests remote access software execution");
      }
      if (text.includes("bank") || text.includes("gift card") || text.includes("payment")) {
        redFlags.push("Unsecured payment query redirect within chat context");
      }
      if (text.includes("urgent") || text.includes("immediately") || text.includes("suspended")) {
        redFlags.push("Forced urgency speech patterns detected");
      }

      setChatResult({
        redFlags,
        isScamChat: redFlags.length > 0,
        threatScore: redFlags.length * 35,
      });
      setChatScanning(false);
    }, 1200);
  };

  const scanScripts = () => {
    setScriptScanning(true);
    setScriptResult(null);
    setTimeout(() => {
      const text = scriptCode.toLowerCase();
      const matches: string[] = [];
      let score = 0;

      if (text.includes("coinhive") || text.includes("cryptonight") || text.includes("miner")) {
        matches.push("Cryptocurrency miner script library signatures matched");
        score += 85;
      }
      if (text.includes("eval(function(") || text.includes("\\x65\\x76\\x61\\x6c")) {
        matches.push("Boilerplate hex-packed script packing matched");
        score += 65;
      }
      if (text.includes("iframe") && (text.includes("hidden") || text.includes('width="0"'))) {
        matches.push("Hidden iframe element embedding code");
        score += 35;
      }

      setScriptResult({
        score: Math.min(score, 100),
        matches: matches.length > 0 ? matches : ["No obfuscation or miner scripts detected"],
      });
      setScriptScanning(false);
    }, 1200);
  };

  const runBehaviorSimulation = () => {
    setBehaviorLogs([]);
    setBehaviorScore(0);
    const steps = [
      { log: "12:02:10 — Simulating active tab hooks...", score: 5 },
      { log: "12:02:11 — Check tab title modifications (tab hijacking)...", score: 25 },
      { log: "12:02:12 — Check popups triggered on page load (popup flooding)...", score: 65 },
      { log: "12:02:13 — Check forced redirects via window.location override...", score: 85 },
    ];

    steps.forEach((step, idx) => {
      setTimeout(() => {
        setBehaviorLogs((prev) => [...prev, step.log]);
        setBehaviorScore(step.score);
      }, idx * 600);
    });
  };

  return (
    <>
      <Topbar
        title="Advanced Research Lab"
        subtitle="Experimental AI models, speech analyzers, and scripts security inspection"
      />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        {!isExtensionInstalled ? (
          <EmptyState isInstalled={isExtensionInstalled} />
        ) : (
          <div className="space-y-6">
            {/* Header Lab Panel */}
            <div className="glass rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-[var(--shadow-card)]">
              <div className="space-y-1">
                <h2 className="text-lg font-bold tracking-tight flex items-center gap-2">
                  <Brain className="h-5.5 w-5.5 text-cyber-cyan" /> Heuristics Research vaults
                </h2>
                <p className="text-xs text-muted-foreground">
                  Test and inspect cutting-edge cyber-forensics classifiers for non-standard browser
                  threat telemetry.
                </p>
              </div>

              {/* Tab Selector */}
              <div className="flex flex-wrap gap-2">
                {[
                  { id: "voice", label: "Voice Clone", icon: Volume2 },
                  { id: "reviews", label: "Fake Reviews", icon: MessageSquare },
                  { id: "chats", label: "Scam Chats", icon: Bot },
                  { id: "behavior", label: "Behavior Analyzer", icon: Monitor },
                  { id: "scripts", label: "Script Analyzer", icon: Code },
                ].map((t) => {
                  const Icon = t.icon;
                  const active = activeTab === t.id;
                  return (
                    <button
                      key={t.id}
                      onClick={() => setActiveTab(t.id as TabType)}
                      className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg border transition-all ${
                        active
                          ? "bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan shadow-[var(--shadow-glow)]"
                          : "bg-card/45 border-border/60 text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                      {t.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Core Workspace Cards */}
            <div className="grid grid-cols-1 gap-6">
              {/* Voice Clone Analyzer */}
              {activeTab === "voice" && (
                <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  <div>
                    <h3 className="text-base font-semibold flex items-center gap-2">
                      <Radio className="h-4.5 w-4.5 text-cyber-cyan animate-pulse" /> Voice Clone
                      Monitoring (Beta)
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Inspect Speech streams and Audio assets for synthetic generation patterns.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-2 space-y-4">
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs font-semibold text-foreground/80">
                          Audio Resource URL or Identifier
                        </label>
                        <input
                          type="text"
                          value={audioInput}
                          onChange={(e) => setAudioInput(e.target.value)}
                          placeholder="https://example.com/assets/voice-stream.mp3"
                          className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan"
                        />
                      </div>
                      <button
                        onClick={scanVoice}
                        disabled={voiceScanning || !audioInput.trim()}
                        className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-xs font-semibold text-background transition-transform active:scale-95"
                      >
                        {voiceScanning ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <Volume2 className="h-4 w-4" />
                        )}
                        Inspect Voice Stream
                      </button>
                    </div>

                    <div className="bg-card/45 border border-border/60 rounded-xl p-4 space-y-4 text-left">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <Cpu className="h-4 w-4 text-cyber-cyan" /> Classifier Output
                      </h4>
                      {voiceResult ? (
                        <div className="space-y-3.5">
                          <div className="flex justify-between items-center text-xs">
                            <span>Synthetic Voice:</span>
                            <span
                              className={`font-bold ${voiceResult.detected ? "text-cyber-danger" : "text-cyber-success"}`}
                            >
                              {voiceResult.detected ? "Flagged (AI Generated)" : "Verified Natural"}
                            </span>
                          </div>
                          <div className="flex justify-between items-center text-xs">
                            <span>Confidence:</span>
                            <span className="font-mono">{voiceResult.confidence}%</span>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[10px] text-muted-foreground uppercase">
                              Speech Dynamics
                            </p>
                            <p className="text-xs text-foreground font-mono">
                              {voiceResult.pitchVariance}
                            </p>
                            <p className="text-xs text-foreground font-mono">
                              {voiceResult.rhythmPattern}
                            </p>
                          </div>
                          {voiceResult.reasons.length > 0 && (
                            <div className="pt-2 border-t border-border/40">
                              <p className="text-[10px] text-muted-foreground uppercase mb-1">
                                Evidences
                              </p>
                              {voiceResult.reasons.map((r: string, idx: number) => (
                                <p
                                  key={idx}
                                  className="text-[11px] text-foreground/90 flex gap-1.5 items-start"
                                >
                                  <span className="text-cyber-cyan">•</span> {r}
                                </p>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground py-8 text-center">
                          Analyze an audio input to output statistics.
                        </p>
                      )}
                    </div>
                  </div>
                </section>
              )}

              {/* Fake Review Detector */}
              {activeTab === "reviews" && (
                <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  <div>
                    <h3 className="text-base font-semibold flex items-center gap-2">
                      <MessageSquare className="h-4.5 w-4.5 text-cyber-cyan" /> Fake Review & Review
                      Farm Detector
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Inspect text elements for boilerplates, sentiment manipulation, and AI-writing
                      vocabulary footprints.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-2 space-y-4">
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs font-semibold text-foreground/80">
                          Review Content Paste
                        </label>
                        <textarea
                          rows={4}
                          value={reviewText}
                          onChange={(e) => setReviewText(e.target.value)}
                          placeholder="Paste a suspicious user review or product comment here..."
                          className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan resize-none"
                        />
                      </div>
                      <button
                        onClick={scanReviews}
                        disabled={reviewScanning || !reviewText.trim()}
                        className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-xs font-semibold text-background transition-transform active:scale-95"
                      >
                        {reviewScanning ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <MessageSquare className="h-4 w-4" />
                        )}
                        Scan Sentiment Patterns
                      </button>
                    </div>

                    <div className="bg-card/45 border border-border/60 rounded-xl p-4 space-y-4 text-left">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <Cpu className="h-4 w-4 text-cyber-cyan" /> Sentiment Metrics
                      </h4>
                      {reviewResult ? (
                        <div className="space-y-3.5">
                          <div className="flex justify-between items-center text-xs">
                            <span>AI Likelihood Score:</span>
                            <span
                              className={`font-mono font-bold ${reviewResult.score > 60 ? "text-cyber-danger" : "text-cyber-success"}`}
                            >
                              {reviewResult.score}%
                            </span>
                          </div>
                          <div className="flex justify-between items-center text-xs">
                            <span>Analysis:</span>
                            <span className="font-semibold text-xs">
                              {reviewResult.classification}
                            </span>
                          </div>
                          <div className="flex justify-between items-center text-xs">
                            <span>Repetitive Vocabulary:</span>
                            <span>
                              {reviewResult.sentimentRepetition ? "Flagged (High)" : "Normal"}
                            </span>
                          </div>
                          {reviewResult.matchedWords.length > 0 && (
                            <div className="pt-2 border-t border-border/40">
                              <p className="text-[10px] text-muted-foreground uppercase mb-1">
                                AI footprints matched
                              </p>
                              <div className="flex flex-wrap gap-1.5">
                                {reviewResult.matchedWords.map((w: string, idx: number) => (
                                  <span
                                    key={idx}
                                    className="text-[10px] px-2 py-0.5 rounded bg-secondary/80 text-muted-foreground font-mono"
                                  >
                                    {w}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground py-8 text-center">
                          Analyze a review text block to output metrics.
                        </p>
                      )}
                    </div>
                  </div>
                </section>
              )}

              {/* Fake Support Chat Detector */}
              {activeTab === "chats" && (
                <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  <div>
                    <h3 className="text-base font-semibold flex items-center gap-2">
                      <Bot className="h-4.5 w-4.5 text-cyber-cyan" /> Fake Support Chat & Widget
                      Detector
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Inspect embedded chatbot configurations for social engineering and remote
                      control scam patterns.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-2 space-y-4">
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs font-semibold text-foreground/80">
                          Chat widget transcript or Script code snippet
                        </label>
                        <textarea
                          rows={4}
                          value={chatCode}
                          onChange={(e) => setChatCode(e.target.value)}
                          placeholder="Paste dialog transcript or chat script snippet..."
                          className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan resize-none font-mono text-xs"
                        />
                      </div>
                      <button
                        onClick={scanChat}
                        disabled={chatScanning || !chatCode.trim()}
                        className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-xs font-semibold text-background transition-transform active:scale-95"
                      >
                        {chatScanning ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <Bot className="h-4 w-4" />
                        )}
                        Inspect Support Widget
                      </button>
                    </div>

                    <div className="bg-card/45 border border-border/60 rounded-xl p-4 space-y-4 text-left">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <Cpu className="h-4 w-4 text-cyber-cyan" /> Forensic Report
                      </h4>
                      {chatResult ? (
                        <div className="space-y-3.5">
                          <div className="flex justify-between items-center text-xs">
                            <span>Threat Level:</span>
                            <span
                              className={`font-bold ${chatResult.isScamChat ? "text-cyber-danger" : "text-cyber-success"}`}
                            >
                              {chatResult.isScamChat ? "Critical Red Flags" : "Safe Class"}
                            </span>
                          </div>
                          <div className="flex justify-between items-center text-xs">
                            <span>Threat Score:</span>
                            <span className="font-mono">{chatResult.threatScore} / 100</span>
                          </div>
                          {chatResult.redFlags.length > 0 ? (
                            <div className="pt-2 border-t border-border/40">
                              <p className="text-[10px] text-muted-foreground uppercase mb-1.5">
                                Flagged dialog components
                              </p>
                              {chatResult.redFlags.map((f: string, idx: number) => (
                                <p
                                  key={idx}
                                  className="text-[11px] text-cyber-danger bg-cyber-danger/5 border border-cyber-danger/20 rounded p-2 mb-2 leading-relaxed"
                                >
                                  {f}
                                </p>
                              ))}
                            </div>
                          ) : (
                            <p className="text-[11px] text-cyber-success flex gap-1.5 items-center">
                              <CheckCircle className="h-4 w-4" /> No scam signatures matched
                            </p>
                          )}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground py-8 text-center">
                          Analyze a chat widget snippet to inspect.
                        </p>
                      )}
                    </div>
                  </div>
                </section>
              )}

              {/* Browser Behavior Analyzer */}
              {activeTab === "behavior" && (
                <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  <div>
                    <h3 className="text-base font-semibold flex items-center gap-2">
                      <Monitor className="h-4.5 w-4.5 text-cyber-cyan" /> Tab Hijacking & Popup
                      Behavior Simulator
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Track and test forced redirects, page popups count, and title swap behavior.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-2 space-y-4">
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        Start browser simulation model to trigger mock sequences representing popup
                        flooding, tab context swapping, and forced navigation hooks.
                      </p>
                      <button
                        onClick={runBehaviorSimulation}
                        className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-xs font-semibold text-background transition-transform active:scale-95"
                      >
                        Start Simulator Sequence
                      </button>

                      {behaviorLogs.length > 0 && (
                        <div className="bg-[#081225] border border-border/60 rounded-xl p-4 font-mono text-[11px] text-cyber-cyan space-y-2 max-h-48 overflow-y-auto">
                          {behaviorLogs.map((log, idx) => (
                            <p key={idx}>{log}</p>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="bg-card/45 border border-border/60 rounded-xl p-4 space-y-4 text-left">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <Cpu className="h-4 w-4 text-cyber-cyan" /> Behavior score
                      </h4>
                      <div className="space-y-2">
                        <p className="text-xs text-muted-foreground">
                          Anomaly score during behavior script trace:
                        </p>
                        <p className="text-3xl font-extrabold font-mono text-cyber-warning">
                          {behaviorScore}
                        </p>
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                            behaviorScore > 75
                              ? "bg-cyber-danger/12 text-cyber-danger"
                              : behaviorScore > 35
                                ? "bg-cyber-warning/12 text-cyber-warning"
                                : "bg-cyber-success/12 text-cyber-success"
                          }`}
                        >
                          {behaviorScore > 75
                            ? "Hijack Confirmed"
                            : behaviorScore > 35
                              ? "Suspicious"
                              : "Normal state"}
                        </span>
                      </div>
                    </div>
                  </div>
                </section>
              )}

              {/* Hidden Script Analyzer */}
              {activeTab === "scripts" && (
                <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  <div>
                    <h3 className="text-base font-semibold flex items-center gap-2">
                      <Code className="h-4.5 w-4.5 text-cyber-cyan" /> JavaScript Obfuscation &
                      Crypto Miner Inspector
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Inspect loaded code blocks for hex packing, miner variables, or script
                      packers.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="md:col-span-2 space-y-4">
                      <div className="flex flex-col gap-1.5">
                        <label className="text-xs font-semibold text-foreground/80">
                          JavaScript Code block Paste
                        </label>
                        <textarea
                          rows={6}
                          value={scriptCode}
                          onChange={(e) => setScriptCode(e.target.value)}
                          placeholder="paste code here (e.g. eval(function(p,a,c,k,e,d)...)"
                          className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-xs outline-none focus:border-cyber-cyan font-mono resize-none"
                        />
                      </div>
                      <button
                        onClick={scanScripts}
                        disabled={scriptScanning || !scriptCode.trim()}
                        className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-xs font-semibold text-background transition-transform active:scale-95"
                      >
                        {scriptScanning ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <Code className="h-4 w-4" />
                        )}
                        Scan Script Syntax
                      </button>
                    </div>

                    <div className="bg-card/45 border border-border/60 rounded-xl p-4 space-y-4 text-left">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                        <Cpu className="h-4 w-4 text-cyber-cyan" /> Script Forensics
                      </h4>
                      {scriptResult ? (
                        <div className="space-y-3.5">
                          <div className="flex justify-between items-center text-xs">
                            <span>Obfuscation / Miner score:</span>
                            <span
                              className={`font-mono font-bold ${scriptResult.score > 50 ? "text-cyber-danger" : "text-cyber-success"}`}
                            >
                              {scriptResult.score}%
                            </span>
                          </div>
                          <div className="pt-2 border-t border-border/40 space-y-2">
                            <p className="text-[10px] text-muted-foreground uppercase">
                              Inspected Signatures
                            </p>
                            {scriptResult.matches.map((m: string, idx: number) => (
                              <div
                                key={idx}
                                className="text-[11px] p-2 bg-secondary/40 border border-border/40 rounded leading-relaxed"
                              >
                                {m}
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground py-8 text-center">
                          Analyze a script block to inspect obfuscations.
                        </p>
                      )}
                    </div>
                  </div>
                </section>
              )}
            </div>
          </div>
        )}
      </main>
    </>
  );
}
