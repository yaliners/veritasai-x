import { Link, useRouterState } from "@tanstack/react-router";
import { Shield, LayoutDashboard, Radar, BarChart3, ListChecks, Settings, Download, Clock, FileText, ShieldAlert, Beaker } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState, useEffect } from "react";

const nav = [
  { to: "/dashboard", label: "Security Center", icon: LayoutDashboard },
  { to: "/threats", label: "Threat Intelligence", icon: Radar },
  { to: "/sandbox", label: "Threat Sandbox", icon: ShieldAlert },
  { to: "/timeline", label: "Security Timeline", icon: Clock },
  { to: "/report", label: "Security Report", icon: FileText },
  { to: "/research", label: "Research Lab", icon: Beaker },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/trusted", label: "Trusted Sites", icon: ListChecks },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppSidebar() {
  const path = useRouterState({ select: (r) => r.location.pathname });
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const handleToggle = () => setIsOpen((o) => !o);
    const handleClose = () => setIsOpen(false);

    window.addEventListener("veritas-toggle-sidebar", handleToggle);
    window.addEventListener("veritas-close-sidebar", handleClose);

    return () => {
      window.removeEventListener("veritas-toggle-sidebar", handleToggle);
      window.removeEventListener("veritas-close-sidebar", handleClose);
    };
  }, []);

  // Close sidebar on path changes
  useEffect(() => {
    setIsOpen(false);
  }, [path]);

  return (
    <>
      {/* Dark overlay backdrop for mobile */}
      {isOpen && (
        <div
          onClick={() => setIsOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity duration-300 lg:hidden"
        />
      )}

      <aside
        className={cn(
          "w-64 shrink-0 flex-col border-r border-border/60 bg-sidebar/80 backdrop-blur-xl transition-transform duration-300 ease-in-out",
          // Desktop styling: always flex & visible, static flow, no translate
          "lg:flex lg:translate-x-0 lg:static lg:z-auto",
          // Mobile styling: absolute fixed layout
          "fixed inset-y-0 left-0 z-50 flex",
          isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
      >
        <Link
          to="/"
          onClick={() => setIsOpen(false)}
          className="flex items-center gap-3 px-6 py-6 hover:opacity-90 transition-opacity"
        >
          <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyber-cyan to-primary shadow-[var(--shadow-glow)]">
            <Shield className="h-5 w-5 text-background" />
            <span className="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full bg-cyber-success pulse-dot" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-tight text-foreground">VeritasShield AI</p>
            <p className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">v1.0.0 · SOC</p>
          </div>
        </Link>

        <nav className="flex-1 space-y-1 px-3">
          <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Operations</p>
          {nav.map((item) => {
            const active = path === item.to;
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setIsOpen(false)}
                className={cn(
                  "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all",
                  active
                    ? "bg-gradient-to-r from-cyber-cyan/15 to-transparent text-cyber-cyan shadow-[inset_2px_0_0_0_var(--cyber-cyan)]"
                    : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="m-3 rounded-xl border border-border/60 bg-card/60 p-4">
          <p className="text-xs font-semibold">Chrome Extension</p>
          <p className="mt-1 text-[11px] text-muted-foreground">Deploy real-time browser protection.</p>
          <Link
            to="/setup"
            onClick={() => setIsOpen(false)}
            className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-3 py-2 text-xs font-semibold text-background transition-transform hover:scale-[1.02]"
          >
            <Download className="h-3.5 w-3.5" />
            Setup Guide
          </Link>
          <p className="mt-2 text-[9px] text-center text-muted-foreground">
            Chrome extension • Manifest V3 • Free
          </p>
        </div>
      </aside>
    </>
  );
}