import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useSettings, clearAll, useExtensionInstalled } from "@/lib/veritas/store";
import { EmptyState } from "@/components/veritas/empty-state";
import { Save, Trash2, RotateCcw, ShieldOff, Moon, Sun, Download, Upload } from "lucide-react";
import type { SecuritySettings } from "@/lib/veritas/types";
import { toast } from "sonner";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — VeritasShield AI" },
      { name: "description", content: "Configure detection modules, alerts, and storage." },
    ],
  }),
  component: SettingsCenter,
});

function SettingsCenter() {
  const [settings, setSettings] = useSettings();
  const isExtensionInstalled = useExtensionInstalled();
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    const activeTheme = document.documentElement.classList.contains("light") ? "light" : "dark";
    setTheme(activeTheme);
  }, []);

  const changeTheme = (mode: "dark" | "light") => {
    setTheme(mode);
    if (mode === "light") {
      document.documentElement.classList.add("light");
      localStorage.setItem("veritas_theme", "light");
    } else {
      document.documentElement.classList.remove("light");
      localStorage.setItem("veritas_theme", "dark");
    }
  };

  function toggleModule(key: keyof SecuritySettings["modules"]) {
    setSettings({ ...settings, modules: { ...settings.modules, [key]: !settings.modules[key] } });
  }

  function toggleControl(key: keyof SecuritySettings["controls"]) {
    setSettings({
      ...settings,
      controls: { ...settings.controls, [key]: !settings.controls[key] },
    });
  }

  function handleSaveSettings() {
    setSettings({
      ...settings,
    });
    toast.success("Settings saved successfully!", {
      description: "Extension configuration has been synchronized.",
      duration: 3000,
    });
  }

  const handleExportHistory = () => {
    try {
      const extData = localStorage.getItem("veritasai_scans") || "[]";
      const blob = new Blob([extData], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `veritasai-backup-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("History exported successfully!");
    } catch (e) {
      toast.error("Failed to export history.");
    }
  };

  const handleImportHistory = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const imported = JSON.parse(e.target?.result as string);
        if (!Array.isArray(imported)) {
          toast.error("Invalid file format. Must be a JSON array.");
          return;
        }

        const existingRaw = localStorage.getItem("veritasai_scans") || "[]";
        const existing = JSON.parse(existingRaw);

        let mergeCount = 0;
        const merged = [...existing];

        imported.forEach((item: any) => {
          if (!item.domain || !item.time) return;
          const duplicate = existing.some(
            (x: any) => x.domain === item.domain && x.time === item.time,
          );
          if (!duplicate) {
            merged.push(item);
            mergeCount++;
          }
        });

        localStorage.setItem("veritasai_scans", JSON.stringify(merged));
        window.dispatchEvent(new CustomEvent("veritas:update", { detail: "veritasai_scans" }));

        toast.success(`Successfully imported ${mergeCount} new scan entries!`);
        setTimeout(() => location.reload(), 1000);
      } catch (err) {
        toast.error("Failed to parse the backup file.");
      }
    };
    reader.readAsText(file);
  };

  const moduleItems: Array<{
    key: keyof SecuritySettings["modules"];
    label: string;
    desc: string;
    isBeta?: boolean;
  }> = [
    {
      key: "phishing",
      label: "Phishing Detector",
      desc: "Scans URLs, login forms, brand impersonation.",
    },
    { key: "scam", label: "Scam Detector", desc: "Crypto, lottery, wire-transfer fraud patterns." },
    { key: "aiContent", label: "AI Content Detector", desc: "Identifies AI-generated scam copy." },
    {
      key: "darkPattern",
      label: "Dark Pattern Detector",
      desc: "Forced urgency, fake scarcity, hidden subs.",
    },
    {
      key: "qrDetector",
      label: "QR Detector",
      desc: "Inspects malicious QR codes on pages.",
      isBeta: true,
    },
    {
      key: "voiceClone",
      label: "Voice Clone Detector",
      desc: "Beta — detects synthetic voice payloads.",
      isBeta: true,
    },
  ];

  const controlItems: Array<{
    key: keyof SecuritySettings["controls"];
    label: string;
    desc: string;
  }> = [
    { key: "autoScan", label: "Auto Scan", desc: "Continuously scan every navigation." },
    { key: "popupAlerts", label: "Popup Alerts", desc: "Show extension badge notifications." },
    {
      key: "overlayAlerts",
      label: "Overlay Alerts",
      desc: "Render full-page warning on dangerous sites.",
    },
  ];

  return (
    <>
      <Topbar title="Settings Center" subtitle="Calibrate detection, alerts, and data retention" />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        {!isExtensionInstalled ? (
          <EmptyState isInstalled={isExtensionInstalled} />
        ) : (
          <>
            <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
              <h2 className="text-base font-semibold">Security Modules</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Enable individual AI detection engines.
              </p>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {moduleItems.map((m) => (
                  <ToggleRow
                    key={m.key}
                    label={m.label}
                    desc={m.desc}
                    value={settings.modules[m.key]}
                    onChange={() => toggleModule(m.key)}
                    isBeta={m.isBeta}
                  />
                ))}
              </div>
            </section>

            <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
              <h2 className="text-base font-semibold">System Controls</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Runtime behavior of the extension.
              </p>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                {controlItems.map((m) => (
                  <ToggleRow
                    key={m.key}
                    label={m.label}
                    desc={m.desc}
                    value={settings.controls[m.key]}
                    onChange={() => toggleControl(m.key)}
                  />
                ))}
              </div>
            </section>

            <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
              <h2 className="text-base font-semibold">Alert Style Settings</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Choose how threat detections are displayed.
              </p>
              <div className="flex flex-wrap gap-4">
                {["Full overlay", "Toast only", "Badge only"].map((style) => {
                  const currentStyle = (settings.controls as any).alertStyle || "Full overlay";
                  const isSelected = currentStyle === style;
                  return (
                    <button
                      key={style}
                      onClick={() => {
                        setSettings({
                          ...settings,
                          controls: {
                            ...settings.controls,
                            alertStyle: style as any,
                          },
                        });
                      }}
                      className={`inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-xs font-semibold transition-all ${
                        isSelected
                          ? "border-cyber-cyan bg-cyber-cyan/15 text-cyber-cyan shadow-[var(--shadow-glow)]"
                          : "border-border/60 bg-card/40 text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {style}
                    </button>
                  );
                })}
              </div>
            </section>

            <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
              <h2 className="text-base font-semibold">Appearance Theme</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Select your interface styling preference.
              </p>
              <div className="flex flex-wrap gap-4">
                <button
                  onClick={() => changeTheme("dark")}
                  className={`inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-xs font-semibold transition-all ${
                    theme === "dark"
                      ? "border-cyber-cyan bg-cyber-cyan/15 text-cyber-cyan shadow-[var(--shadow-glow)]"
                      : "border-border/60 bg-card/40 text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Moon className="h-4 w-4" />
                  Dark Cybersecurity (Default)
                </button>
                <button
                  onClick={() => changeTheme("light")}
                  className={`inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-xs font-semibold transition-all ${
                    theme === "light"
                      ? "border-primary bg-primary/15 text-primary"
                      : "border-border/60 bg-card/40 text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Sun className="h-4 w-4" />
                  Light Tech Shield
                </button>
              </div>
            </section>

            <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
              <h2 className="text-base font-semibold">Import & Export Scan History</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Backup or restore your local scan databases.
              </p>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={handleExportHistory}
                  className="inline-flex items-center gap-2 rounded-lg border border-cyber-cyan/40 bg-cyber-cyan/10 px-4 py-2 text-sm font-semibold text-cyber-cyan hover:bg-cyber-cyan/20 active:scale-95 transition-transform"
                >
                  <Download className="h-4 w-4" /> Export History
                </button>
                <label className="inline-flex items-center gap-2 rounded-lg border border-cyber-cyan/40 bg-cyber-cyan/10 px-4 py-2 text-sm font-semibold text-cyber-cyan hover:bg-cyber-cyan/20 active:scale-95 transition-transform cursor-pointer">
                  <Upload className="h-4 w-4" /> Import History
                  <input
                    type="file"
                    accept=".json"
                    onChange={handleImportHistory}
                    className="hidden"
                  />
                </label>
              </div>
            </section>

            <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
              <h2 className="text-base font-semibold">Data & Reset</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Destructive actions are irreversible.
              </p>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={handleSaveSettings}
                  className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-sm font-semibold text-background transition-transform active:scale-95"
                >
                  <Save className="h-4 w-4" /> Save Settings
                </button>
                <button
                  onClick={() => {
                    if (confirm("Clear threat history?")) {
                      localStorage.removeItem("veritasai_scans");
                      toast.success("Threat history cleared successfully!");
                      setTimeout(() => location.reload(), 800);
                    }
                  }}
                  className="inline-flex items-center gap-2 rounded-lg border border-cyber-warning/40 bg-cyber-warning/10 px-4 py-2 text-sm font-semibold text-cyber-warning transition-transform active:scale-95"
                >
                  <Trash2 className="h-4 w-4" /> Clear Threat History
                </button>
                <button
                  onClick={() => {
                    if (confirm("Clear trusted domains?")) {
                      localStorage.removeItem("veritas:trusted");
                      toast.success("Trusted domains cleared successfully!");
                      setTimeout(() => location.reload(), 800);
                    }
                  }}
                  className="inline-flex items-center gap-2 rounded-lg border border-cyber-warning/40 bg-cyber-warning/10 px-4 py-2 text-sm font-semibold text-cyber-warning transition-transform active:scale-95"
                >
                  <ShieldOff className="h-4 w-4" /> Clear Trusted Domains
                </button>
                <button
                  onClick={() => {
                    if (confirm("Reset entire extension?")) {
                      clearAll();
                      localStorage.removeItem("veritasai_scans");
                      toast.success("Settings and extension database reset successfully!");
                      setTimeout(() => location.reload(), 800);
                    }
                  }}
                  className="inline-flex items-center gap-2 rounded-lg border border-cyber-danger/40 bg-cyber-danger/10 px-4 py-2 text-sm font-semibold text-cyber-danger transition-transform active:scale-95"
                >
                  <RotateCcw className="h-4 w-4" /> Reset Extension
                </button>
              </div>
            </section>
          </>
        )}
      </main>
    </>
  );
}

function ToggleRow({
  label,
  desc,
  value,
  onChange,
  isBeta,
}: {
  label: string;
  desc: string;
  value: boolean;
  onChange: () => void;
  isBeta?: boolean;
}) {
  return (
    <label
      className={`flex items-start justify-between gap-3 rounded-xl border border-border/60 bg-card/40 p-4 transition-colors ${isBeta ? "opacity-60 cursor-not-allowed" : "cursor-pointer hover:border-cyber-cyan/40"}`}
    >
      <div>
        <p className="text-sm font-semibold flex items-center gap-2">
          {label}
          {isBeta && (
            <span className="text-[9px] bg-cyber-warning/20 text-cyber-warning px-1.5 py-0.5 rounded border border-cyber-warning/40 uppercase tracking-wide">
              Beta
            </span>
          )}
        </p>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {isBeta ? "Coming in v3.0 — tool is disabled." : desc}
        </p>
      </div>
      <div
        className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${value && !isBeta ? "bg-cyber-cyan" : "bg-secondary"}`}
      >
        <input
          type="checkbox"
          checked={isBeta ? false : value}
          onChange={isBeta ? undefined : onChange}
          disabled={isBeta}
          className="sr-only"
        />
        <span
          className={`absolute top-0.5 h-5 w-5 rounded-full bg-background transition-all ${value && !isBeta ? "left-[22px]" : "left-0.5"}`}
        />
      </div>
    </label>
  );
}
