import { Activity, Search, Bell, X, Menu } from "lucide-react";
import { useState, useRef, useEffect } from "react";

interface TopbarProps {
  title: string;
  subtitle?: string;
  onSearch?: (query: string) => void;
  notificationCount?: number;
  notifications?: Array<{ id: string; domain: string; risk: string; timestamp: number }>;
}

export function Topbar({ title, subtitle, onSearch, notificationCount = 0, notifications = [] }: TopbarProps) {
  const [showNotifications, setShowNotifications] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    }
    if (showNotifications) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [showNotifications]);

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-border/60 bg-background/70 px-4 py-4 backdrop-blur-xl lg:px-8">
      <div className="flex items-center gap-3">
        {/* Hamburger Menu Button */}
        <button
          onClick={() => window.dispatchEvent(new CustomEvent("veritas-toggle-sidebar"))}
          className="flex lg:hidden h-9 w-9 items-center justify-center rounded-lg border border-border/60 bg-[#0F172A] text-muted-foreground hover:text-foreground transition-colors"
          aria-label="Toggle Menu"
        >
          <Menu className="h-5 w-5" />
        </button>
        <div>
          <p className="text-[10px] uppercase tracking-[0.25em] text-cyber-cyan">VeritasShield AI</p>
          <h1 className="text-xl font-bold tracking-tight text-lg sm:text-xl">{title}</h1>
          {subtitle && <p className="text-[10px] sm:text-xs text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="hidden md:flex items-center gap-2 rounded-lg border border-border/60 bg-card/40 px-3 py-1.5">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="Quick search threats…"
            onChange={(e) => onSearch?.(e.target.value)}
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
        <div className="relative hidden md:block" ref={notifRef}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-border/60 bg-card/40 text-muted-foreground hover:text-foreground"
          >
            <Bell className="h-4 w-4" />
            {notificationCount > 0 && <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-cyber-danger" />}
          </button>
          {showNotifications && (
            <div className="absolute right-0 top-11 w-80 rounded-lg border border-border/60 bg-card/95 backdrop-blur shadow-lg">
              <div className="flex items-center justify-between border-b border-border/40 px-4 py-3">
                <h3 className="text-sm font-semibold">Notifications</h3>
                <button onClick={() => setShowNotifications(false)} className="text-muted-foreground hover:text-foreground">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="max-h-96 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="py-8 text-center text-xs text-muted-foreground">No new notifications</div>
                ) : (
                  <div className="divide-y divide-border/40">
                    {notifications.map((n) => (
                      <div key={n.id} className="px-4 py-3 text-xs hover:bg-card/50">
                        <div className="font-medium truncate">{n.domain}</div>
                        <div className="mt-1 flex items-center justify-between">
                          <span className={n.risk === "DANGEROUS" ? "text-cyber-danger" : "text-cyber-warning"}>{n.risk}</span>
                          <span className="text-muted-foreground">{relTime(n.timestamp)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
        <button className="hidden md:flex h-9 w-9 items-center justify-center rounded-lg border border-border/60 bg-card/40 text-cyber-cyan">
          <Activity className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}

function relTime(ts: number) {
  const diff = Date.now() - ts;
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}