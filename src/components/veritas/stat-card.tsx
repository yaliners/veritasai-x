import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface Props {
  label: string;
  value: string | number;
  hint?: string;
  icon: LucideIcon;
  accent?: "cyan" | "success" | "warning" | "danger";
  trend?: string;
}

const ACCENTS = {
  cyan: "text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/30",
  success: "text-cyber-success bg-cyber-success/10 border-cyber-success/30",
  warning: "text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30",
  danger: "text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30",
};

export function StatCard({ label, value, hint, icon: Icon, accent = "cyan", trend }: Props) {
  return (
    <div className="glass relative overflow-hidden rounded-2xl p-5 shadow-[var(--shadow-card)]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">{label}</p>
          <p className="mt-2 text-3xl font-bold tracking-tight mono">{value}</p>
          {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
        </div>
        <div className={cn("flex h-11 w-11 items-center justify-center rounded-xl border", ACCENTS[accent])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      {trend && (
        <p className="mt-3 text-xs font-medium text-cyber-success">{trend}</p>
      )}
      <div className="pointer-events-none absolute -bottom-12 -right-12 h-32 w-32 rounded-full bg-cyber-cyan/5 blur-2xl" />
    </div>
  );
}