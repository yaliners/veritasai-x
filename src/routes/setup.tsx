import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import {
  Download,
  Shield,
  ShieldCheck,
  HelpCircle,
  Sun,
  Moon,
  CheckCircle2,
  ArrowRight,
  RefreshCw,
} from "lucide-react";

export const Route = createFileRoute("/setup")({
  head: () => ({
    meta: [
      { title: "Extension Setup — VeritasShield AI" },
      {
        name: "description",
        content: "Learn how to install and configure the VeritasShield AI browser extension.",
      },
    ],
  }),
  component: SetupPage,
});

function SetupPage() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [isExtensionInstalled, setIsExtensionInstalled] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [checked, setChecked] = useState(false);

  // Load initial theme from DOM or localStorage
  useEffect(() => {
    const activeTheme = document.documentElement.classList.contains("light") ? "light" : "dark";
    setTheme(activeTheme);
    checkExtensionStatus();

    const focusHandler = () => checkExtensionStatus();
    window.addEventListener("focus", focusHandler);
    return () => window.removeEventListener("focus", focusHandler);
  }, []);

  const checkExtensionStatus = (callback?: (active: boolean) => void) => {
    let active = false;
    const handlePong = () => {
      active = true;
      setIsExtensionInstalled(true);
      setChecked(true);
      callback?.(true);
    };
    window.addEventListener("veritas_pong", handlePong);
    window.dispatchEvent(new CustomEvent("veritas_ping"));

    setTimeout(() => {
      if (!active) {
        setIsExtensionInstalled(false);
        setChecked(true);
        callback?.(false);
      }
      window.removeEventListener("veritas_pong", handlePong);
    }, 250);
  };

  const handleVerify = () => {
    setVerificationLoading(true);
    checkExtensionStatus(() => {
      setVerificationLoading(false);
    });
  };

  const toggleTheme = (mode: "dark" | "light") => {
    setTheme(mode);
    if (mode === "light") {
      document.documentElement.classList.add("light");
      localStorage.setItem("veritas_theme", "light");
    } else {
      document.documentElement.classList.remove("light");
      localStorage.setItem("veritas_theme", "dark");
    }
  };

  const handleDownload = () => {
    const link = document.createElement("a");
    link.href = "/veritasai-extension.zip";
    link.download = "veritasai-extension.zip";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen w-full bg-gradient-to-b from-background via-background to-background/95">
      <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
        {/* Header Bar */}
        <div className="flex items-center justify-between border-b border-border/40 pb-6 mb-10">
          <Link to="/" className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyber-cyan to-primary shadow-[var(--shadow-glow)]">
              <Shield className="h-5 w-5 text-background" />
              <span className="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full bg-cyber-success" />
            </div>
            <div>
              <span className="text-sm font-bold tracking-tight text-foreground block">
                VeritasShield AI
              </span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest block">
                Edge Security
              </span>
            </div>
          </Link>

          {/* Theme Switcher Toggle */}
          <div className="flex items-center gap-1 rounded-lg border border-border/60 bg-card/60 p-1">
            <button
              onClick={() => toggleTheme("dark")}
              className={`flex h-8 items-center gap-2 rounded px-3 text-xs font-medium transition-colors ${
                theme === "dark"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Moon className="h-3.5 w-3.5" />
              Dark Mode
            </button>
            <button
              onClick={() => toggleTheme("light")}
              className={`flex h-8 items-center gap-2 rounded px-3 text-xs font-medium transition-colors ${
                theme === "light"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Sun className="h-3.5 w-3.5" />
              Light Mode
            </button>
          </div>
        </div>

        {/* Content Section */}
        <div className="grid gap-8 md:grid-cols-3">
          {/* Instructions Column (Main) */}
          <div className="md:col-span-2 space-y-6">
            <div className="glass rounded-2xl p-6 md:p-8">
              <h1 className="text-2xl font-bold tracking-tight text-foreground mb-2">
                Extension Setup Guide
              </h1>
              <p className="text-sm text-muted-foreground mb-6">
                Protect your browser in real time. Follow these steps to load the VeritasShield AI
                extension onto Chrome or Edge.
              </p>

              {/* Step checklist */}
              <div className="space-y-6">
                {/* Step 1 */}
                <div className="flex gap-4">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-bold text-primary">
                    1
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">
                      Download the Extension Package
                    </h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Click the button below to download the latest packed ZIP containing the
                      VeritasShield Manifest V3 security extension.
                    </p>
                    <button
                      onClick={handleDownload}
                      className="mt-3 inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-xs font-semibold text-background hover:opacity-90"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download veritasai-extension.zip
                    </button>
                  </div>
                </div>

                {/* Step 2 */}
                <div className="flex gap-4">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-bold text-primary">
                    2
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-sm font-semibold text-foreground">
                      Install in Developer Mode
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Since this is a custom security package, load it unpacked directly in Chrome:
                    </p>
                    <ul className="list-decimal pl-4 text-xs text-muted-foreground space-y-1.5">
                      <li>
                        Extract/unzip the downloaded{" "}
                        <code className="rounded bg-muted px-1 py-0.5 mono text-[10px]">
                          veritasai-extension.zip
                        </code>{" "}
                        file to a folder on your computer.
                      </li>
                      <li>
                        Open a new browser tab and navigate to{" "}
                        <code className="rounded bg-muted px-1 py-0.5 mono text-[10px]">
                          chrome://extensions
                        </code>
                        .
                      </li>
                      <li>
                        In the top-right corner, toggle the **Developer Mode** switch to **ON**.
                      </li>
                      <li>In the top-left corner, click the **Load unpacked** button.</li>
                      <li>
                        Select the extracted extension folder (the directory containing{" "}
                        <code className="text-[10px]">manifest.json</code>).
                      </li>
                    </ul>
                  </div>
                </div>

                {/* Step 3 */}
                <div className="flex gap-4">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-bold text-primary">
                    3
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">Verify & Complete</h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      After installation, verify that the extension is actively running local edge
                      scans.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Connection Checker Card */}
          <div className="space-y-6">
            <div className="glass rounded-2xl p-6 shadow-[var(--shadow-card)] text-center">
              <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-4">
                Connection Status
              </h2>

              <div className="mb-6 flex flex-col items-center justify-center">
                {checked && isExtensionInstalled ? (
                  <>
                    <div className="flex h-16 w-16 items-center justify-center rounded-full bg-cyber-success/10 text-cyber-success mb-3">
                      <ShieldCheck className="h-10 w-10 animate-bounce" />
                    </div>
                    <span className="text-sm font-bold text-cyber-success">Shield Active</span>
                    <p className="mt-1 text-xs text-muted-foreground max-w-[200px] mx-auto">
                      Edge threat detection is connected and running locally.
                    </p>
                  </>
                ) : (
                  <>
                    <div className="flex h-16 w-16 items-center justify-center rounded-full bg-cyber-danger/10 text-cyber-danger mb-3">
                      <Shield className="h-10 w-10 opacity-70" />
                    </div>
                    <span className="text-sm font-bold text-cyber-danger">Setup Pending</span>
                    <p className="mt-1 text-xs text-muted-foreground max-w-[200px] mx-auto">
                      Extension not detected. Please follow the instructions to install.
                    </p>
                  </>
                )}
              </div>

              <div className="space-y-3">
                <button
                  onClick={handleVerify}
                  disabled={verificationLoading}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-border bg-card/60 px-4 py-2 text-xs font-semibold hover:bg-card transition-colors disabled:opacity-50"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${verificationLoading ? "animate-spin" : ""}`}
                  />
                  {verificationLoading ? "Verifying..." : "Verify Connection"}
                </button>

                <Link
                  to="/dashboard"
                  className={`w-full inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2.5 text-xs font-bold text-background shadow-[var(--shadow-glow)] transition-transform ${
                    isExtensionInstalled ? "hover:scale-[1.02]" : "opacity-60 cursor-not-allowed"
                  }`}
                >
                  Go to Security Center
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>

            {/* Quick Tips */}
            <div className="glass rounded-2xl p-6">
              <div className="flex items-center gap-2 text-xs font-bold text-cyber-cyan mb-2">
                <HelpCircle className="h-4 w-4" />
                <span>Quick Tip</span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Once loaded, pin the VeritasShield AI icon to your extension bar. You can click the
                icon at any time to check threat scores and view heuristic reasons for active pages!
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
