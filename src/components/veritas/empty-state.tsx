import { Download, Shield, Radio, Loader2 } from "lucide-react";

export function EmptyState({ isInstalled = false }: { isInstalled?: boolean }) {
  const handleDownload = () => {
    const link = document.createElement("a");
    link.href = "/veritasai-extension.zip";
    link.download = "veritasai-extension.zip";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  if (!isInstalled) {
    return (
      <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <div className="rounded-full bg-cyber-danger/10 p-6 mb-4 border border-cyber-danger/20 relative">
          <Shield className="h-12 w-12 text-cyber-danger" />
          <span className="absolute right-0 top-0 flex h-3.5 w-3.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-danger opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-cyber-danger"></span>
          </span>
        </div>

        <h3 className="text-lg font-bold text-foreground mb-2">Extension Not Detected</h3>

        <p className="text-sm text-muted-foreground max-w-sm mb-6 leading-relaxed">
          Install the VeritasShield AI extension to enable live edge scanner monitoring and view real-time threat intelligence here.
        </p>

        <div className="flex flex-col items-center gap-2">
          <button
            onClick={handleDownload}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-5 py-2.5 text-xs font-bold text-background hover:shadow-lg hover:shadow-cyber-cyan/30 active:scale-95 transition-all"
          >
            <Download className="h-4 w-4" />
            Download Veritas Extension
          </button>
          <p className="text-[10px] text-muted-foreground">Chrome extension • Manifest V3 • Free</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
      <div className="relative mb-8 flex items-center justify-center h-28 w-28">
        {/* Animated outer sonar ring */}
        <div className="absolute inset-0 rounded-full border border-cyber-cyan/40 animate-ping opacity-25"></div>
        {/* Animated mid sonar ring */}
        <div className="absolute inset-2 rounded-full border border-cyber-cyan/30 animate-pulse opacity-45"></div>
        {/* Central glowing icon container */}
        <div className="relative flex h-16 w-16 items-center justify-center rounded-full bg-cyber-cyan/10 border border-cyber-cyan/40 shadow-[0_0_20px_rgba(0,216,255,0.2)]">
          <Radio className="h-7 w-7 text-cyber-cyan animate-pulse" />
        </div>
        {/* Small pulsing indicator in top right of sonar */}
        <span className="absolute right-5 top-5 flex h-3 w-3">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-success opacity-75"></span>
          <span className="relative inline-flex rounded-full h-3 w-3 bg-cyber-success"></span>
        </span>
      </div>

      <h3 className="text-lg font-bold text-foreground mb-2 tracking-wide flex items-center gap-2">
        <Loader2 className="h-4 w-4 text-cyber-cyan animate-spin" />
        Waiting for Scans...
      </h3>

      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyber-success/10 border border-cyber-success/35 text-cyber-success text-[10px] font-bold uppercase tracking-wider mb-4 animate-pulse">
        Active Monitoring Enabled
      </div>

      <p className="text-sm text-muted-foreground max-w-sm leading-relaxed mb-4">
        VeritasShield AI has connected successfully. Browse web pages in other tabs to trigger real-time edge security threat scans.
      </p>
    </div>
  );
}
