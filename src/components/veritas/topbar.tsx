import { Activity, Search, Bell } from "lucide-react";

export function Topbar({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-border/60 bg-background/70 px-4 py-4 backdrop-blur-xl lg:px-8">
      <div>
        <p className="text-[10px] uppercase tracking-[0.25em] text-cyber-cyan">VeritasAI X</p>
        <h1 className="text-xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">
        <div className="hidden md:flex items-center gap-2 rounded-lg border border-border/60 bg-card/40 px-3 py-1.5">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="Quick search threats…"
            className="w-56 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-cyber-success/30 bg-cyber-success/10 px-3 py-1.5 text-xs font-semibold text-cyber-success">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyber-success opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-cyber-success" />
          </span>
          ENGINE LIVE
        </div>
        <button className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-border/60 bg-card/40 text-muted-foreground hover:text-foreground">
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-cyber-danger" />
        </button>
        <button className="flex h-9 w-9 items-center justify-center rounded-lg border border-border/60 bg-card/40 text-cyber-cyan">
          <Activity className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}