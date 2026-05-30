import { cn } from "@/lib/utils";
import type { Risk } from "@/lib/veritas/types";
import { ShieldCheck, ShieldAlert, ShieldX, Shield } from "lucide-react";

const STYLES: Record<Risk, { cls: string; label: string }> = {
  SAFE: { cls: "bg-cyber-success/15 text-cyber-success border-cyber-success/30", label: "Safe" },
  SUSPICIOUS: { cls: "bg-cyber-warning/15 text-cyber-warning border-cyber-warning/30", label: "Suspicious" },
  DANGEROUS: { cls: "bg-cyber-danger/15 text-cyber-danger border-cyber-danger/40", label: "Dangerous" },
  TRUSTED: { cls: "bg-cyber-cyan/15 text-cyber-cyan border-cyber-cyan/40", label: "Trusted" },
};

export function RiskBadge({ risk, className }: { risk: Risk; className?: string }) {
  const s = STYLES[risk];
  const Icon = risk === "DANGEROUS" ? ShieldX : risk === "SUSPICIOUS" ? ShieldAlert : risk === "TRUSTED" ? ShieldCheck : Shield;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider", s.cls, className)}>
      <Icon className="h-3 w-3" />
      {s.label}
    </span>
  );
}