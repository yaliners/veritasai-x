import { Download } from "lucide-react";

export function EmptyState({ isInstalled = false }: { isInstalled?: boolean }) {
  const handleDownload = () => {
    const link = document.createElement("a");
    link.href = "/veritasai-extension.zip";
    link.download = "veritasai-extension.zip";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div className="rounded-full bg-cyber-cyan/10 p-6 mb-4">
        <svg className="h-12 w-12 text-cyber-cyan" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>

      <h3 className="text-lg font-semibold text-foreground mb-2">
        No scan data yet
      </h3>

      <p className="text-sm text-muted-foreground text-center max-w-sm mb-6">
        {isInstalled 
          ? "The VeritasShield AI extension is active. Start browsing websites to see real-time threat intelligence and metrics here."
          : "Install the VeritasShield AI extension and browse some websites to see real threat data here"
        }
      </p>

      {!isInstalled && (
        <div className="flex flex-col items-center gap-2">
          <button
            onClick={handleDownload}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-cyber-cyan/80 px-4 py-2 text-sm font-semibold text-cyber-dark hover:shadow-lg hover:shadow-cyber-cyan/40 transition-shadow"
          >
            <Download className="h-4 w-4" />
            Download Extension
          </button>
          <p className="text-[10px] text-muted-foreground">
            Chrome extension • Manifest V3 • Free
          </p>
        </div>
      )}
    </div>
  );
}
