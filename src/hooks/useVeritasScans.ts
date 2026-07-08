import { useEffect, useState } from "react";
import type { ThreatRecord, DetectionModule } from "@/lib/veritas/types";

export type ScanRecord = ThreatRecord;

export function useVeritasScans() {
  const [scans, setScans] = useState<ThreatRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<number>(Date.now());

  const loadScans = () => {
    try {
      const extData = localStorage.getItem("veritasai_scans");
      if (extData) {
        const rawList = JSON.parse(extData);
        if (Array.isArray(rawList)) {
          const mapped = rawList.map((s: any, i: number) => {
            let confValue = s.score;
            if (s.mlConfidence) {
              const parsed = parseInt(s.mlConfidence);
              if (!isNaN(parsed)) confValue = parsed;
            }
            return {
              id: s.id || `scan_${i}_${s.time || Date.now()}`,
              url: s.url || "",
              domain: s.domain || "",
              risk: s.risk || "SAFE",
              score: s.score || 0,
              trustScore: s.trustScore || 100,
              confidence: confValue,
              aiPrediction: s.aiPrediction || "",
              mlRisk: s.mlRisk || "Low",
              module: (s.module || "Trust Engine") as DetectionModule,
              reasons: s.reasons || [],
              severity:
                s.score >= 85
                  ? "Critical"
                  : s.score >= 65
                    ? "High"
                    : s.score >= 35
                      ? "Medium"
                      : "Low",
              timestamp: s.time || Date.now(),
              confirmed: s.confirmed,
              falsePositive: s.falsePositive,
            } as ThreatRecord;
          });
          setScans(mapped);
        }
      } else {
        setScans([]);
      }
    } catch (e) {
      console.error("Error loading veritasai_scans:", e);
      setScans([]);
    } finally {
      setLoading(false);
      setLastUpdated(Date.now());
    }
  };

  useEffect(() => {
    loadScans();

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === "veritasai_scans") {
        loadScans();
      }
    };

    window.addEventListener("storage", handleStorageChange);

    const handleCustomUpdate = (e: Event) => {
      const d = (e as CustomEvent).detail;
      if (d === "veritasai_scans" || d === "veritas:threats" || d === "*") {
        loadScans();
      }
    };
    window.addEventListener("veritas:update", handleCustomUpdate);

    // Auto-refresh every 10 seconds as backup
    const interval = setInterval(loadScans, 10000);

    return () => {
      window.removeEventListener("storage", handleStorageChange);
      window.removeEventListener("veritas:update", handleCustomUpdate);
      clearInterval(interval);
    };
  }, []);

  const stats = {
    total: scans.length,
    dangerous: scans.filter((s) => s.risk === "DANGEROUS").length,
    suspicious: scans.filter((s) => s.risk === "SUSPICIOUS").length,
    safe: scans.filter((s) => s.risk === "SAFE" || s.risk === "TRUSTED").length,
    confirmed: scans.filter((s) => s.confirmed).length,
    falsePositives: scans.filter((s) => s.falsePositive).length,
    accuracy:
      scans.filter((s) => s.confirmed).length + scans.filter((s) => s.falsePositive).length > 0
        ? Math.round(
            (scans.filter((s) => s.confirmed).length /
              (scans.filter((s) => s.confirmed).length +
                scans.filter((s) => s.falsePositive).length)) *
              100,
          )
        : 100,
  };

  return { scans, stats, loading, lastUpdated, refresh: loadScans };
}
