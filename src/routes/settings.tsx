import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useSettings, clearAll } from "@/lib/veritas/store";
import { Save, Trash2, RotateCcw, ShieldOff, Moon, Sun } from "lucide-react";
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
    setSettings({ ...settings, controls: { ...settings.controls, [key]: !settings.controls[key] } });
  }

  function handleSaveSettings() {
    setSettings(settings);
    toast.success("Settings saved successfully!", {
      description: "Extension configuration has been synchronized.",
      duration: 3000,
    });
  }

  const moduleItems: Array<{ key: keyof SecuritySettings["modules"]; label: string; desc: string }> = [
    { key: "phishing", label: "Phishing Detector", desc: "Scans URLs, login forms, brand impersonation." },
    { key: "scam", label: "Scam Detector", desc: "Crypto, lottery, wire-transfer fraud patterns." },
    { key: "aiContent", label: "AI Content Detector", desc: "Identifies AI-generated scam copy." },
    { key: "darkPattern", label: "Dark Pattern Detector", desc: "Forced urgency, fake scarcity, hidden subs." },
    { key: "qrDetector", label: "QR Detector", desc: "Inspects malicious QR codes on pages." },
    { key: "voiceClone", label: "Voice Clone Detector", desc: "Beta — detects synthetic voice payloads." },
  ];

  const controlItems: Array<{ key: keyof SecuritySettings["controls"]; label: string; desc: string }> = [
    { key: "autoScan", label: "Auto Scan", desc: "Continuously scan every navigation." },
    { key: "popupAlerts", label: "Popup Alerts", desc: "Show extension badge notifications." },
    { key: "overlayAlerts", label: "Overlay Alerts", desc: "Render full-page warning on dangerous sites." },
  ];

  return (
    <>
      <Topbar title="Settings Center" subtitle="Calibrate detection, alerts, and data retention" />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <h2 className="text-base font-semibold">Security Modules</h2>
          <p className="mb-4 text-xs text-muted-foreground">Enable individual AI detection engines.</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {moduleItems.map((m) => (
              <ToggleRow key={m.key} label={m.label} desc={m.desc} value={settings.modules[m.key]} onChange={() => toggleModule(m.key)} />
            ))}
          </div>
        </section>

        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <h2 className="text-base font-semibold">System Controls</h2>
          <p className="mb-4 text-xs text-muted-foreground">Runtime behavior of the extension.</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            {controlItems.map((m) => (
              <ToggleRow key={m.key} label={m.label} desc={m.desc} value={settings.controls[m.key]} onChange={() => toggleControl(m.key)} />
            ))}
          </div>
        </section>

        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <h2 className="text-base font-semibold">Appearance Theme</h2>
          <p className="mb-4 text-xs text-muted-foreground">Select your interface styling preference.</p>
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
          <h2 className="text-base font-semibold">Data & Reset</h2>
          <p className="mb-4 text-xs text-muted-foreground">Destructive actions are irreversible.</p>
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
                  localStorage.removeItem("veritas:threats");
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
      </main>
    </>
  );
}

function ToggleRow({ label, desc, value, onChange }: { label: string; desc: string; value: boolean; onChange: () => void }) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-3 rounded-xl border border-border/60 bg-card/40 p-4 transition-colors hover:border-cyber-cyan/40">
      <div>
        <p className="text-sm font-semibold">{label}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">{desc}</p>
      </div>
      <div className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${value ? "bg-cyber-cyan" : "bg-secondary"}`}>
        <input type="checkbox" checked={value} onChange={onChange} className="sr-only" />
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-background transition-all ${value ? "left-[22px]" : "left-0.5"}`} />
      </div>
    </label>
  );
}