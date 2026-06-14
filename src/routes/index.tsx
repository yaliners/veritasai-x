import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield, ShieldCheck, Brain, Zap } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "VeritasShield AI — Real-time Browser Security" },
      { name: "description", content: "AI-powered protection from phishing, scams, and malicious content." },
    ],
  }),
  component: LandingPage,
});

function LandingPage() {
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
      <div className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8">
        {/* Logo */}
        <div className="mb-16 flex items-center justify-center">
          <div className="relative flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-cyber-cyan to-primary">
            <Shield className="h-6 w-6 text-background" />
            <span className="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full bg-cyber-success" />
          </div>
          <span className="ml-3 text-xl font-bold tracking-tight text-foreground">VeritasShield AI</span>
        </div>

        {/* Hero Section */}
        <div className="mb-20 text-center">
          <h1 className="text-5xl sm:text-6xl font-bold tracking-tight text-foreground mb-6">
            VeritasShield AI
          </h1>
          <p className="text-xl sm:text-2xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Real-time AI threat protection for your browser
          </p>
          <p className="text-sm text-muted-foreground max-w-xl mx-auto">
            Detect phishing, scams, malicious content, and dark patterns with explainable AI. Runs locally on your device — your data never leaves your browser.
          </p>
        </div>

        {/* Feature Cards */}
        <div className="mb-20 grid gap-6 md:grid-cols-3">
          <FeatureCard
            icon={<Zap className="h-6 w-6 text-cyber-cyan" />}
            title="8 Threat Modules"
            description="Comprehensive detection across phishing, scams, AI-generated fraud, dark patterns, and more."
          />
          <FeatureCard
            icon={<Brain className="h-6 w-6 text-cyber-cyan" />}
            title="Edge AI — runs locally"
            description="All threat detection happens on your device. Lightning-fast analysis without cloud dependencies."
          />
          <FeatureCard
            icon={<ShieldCheck className="h-6 w-6 text-cyber-cyan" />}
            title="Explainable detections"
            description="Understand exactly why a threat was flagged with detailed forensics and confidence scoring."
          />
        </div>

        {/* CTA Buttons */}
        <div className="flex flex-col items-center justify-center gap-4">
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Link
              to="/setup"
              className="px-8 py-3 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary text-background font-semibold shadow-md hover:opacity-90 text-center"
            >
              Get Started / Setup
            </Link>
            <Link
              to="/dashboard"
              className="px-8 py-3 rounded-lg border border-border/60 bg-card/40 text-foreground font-semibold hover:bg-card/60"
            >
              Open Dashboard
            </Link>
          </div>
          <p className="text-xs text-muted-foreground">
            Chrome extension • Manifest V3 • Free •{" "}
            <a
              href="/VeritasShield-Project-Report.pdf"
              className="text-cyber-cyan hover:underline ml-1"
            >
              Download Project Report
            </a>
          </p>
        </div>

        {/* Footer Text */}
        <div className="mt-20 pt-12 border-t border-border/40 text-center">
          <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Made with focus on</p>
          <p className="text-sm text-muted-foreground">Security • Privacy • Transparency</p>
        </div>
      </div>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-border/60 bg-card/40 p-8 backdrop-blur">
      <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-lg bg-cyber-cyan/10">
        {icon}
      </div>
      <h3 className="text-lg font-semibold text-foreground mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  );
}
