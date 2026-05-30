import { useEffect, useState, useCallback } from "react";
import type { ThreatRecord, TrustedSite, SecuritySettings } from "./types";

const THREATS_KEY = "veritas:threats";
const TRUSTED_KEY = "veritas:trusted";
const SETTINGS_KEY = "veritas:settings";

const DEFAULT_SETTINGS: SecuritySettings = {
  modules: { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false },
  controls: { autoScan: true, popupAlerts: true, overlayAlerts: true },
};

const DEFAULT_TRUSTED: TrustedSite[] = [];

function read<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function write<T>(key: string, value: T) {
  if (typeof window === "undefined") return;
  localStorage.setItem(key, JSON.stringify(value));
  window.dispatchEvent(new CustomEvent("veritas:update", { detail: key }));
}

function useVeritasStore<T>(key: string, initial: () => T) {
  const [value, setValue] = useState<T>(initial);

  useEffect(() => {
    setValue(read<T>(key, initial()));
    const handler = (e: Event) => {
      const d = (e as CustomEvent).detail;
      if (d === key) setValue(read<T>(key, initial()));
    };
    window.addEventListener("veritas:update", handler);
    return () => window.removeEventListener("veritas:update", handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const update = useCallback(
    (next: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const computed = typeof next === "function" ? (next as (p: T) => T)(prev) : next;
        write(key, computed);
        return computed;
      });
    },
    [key],
  );

  return [value, update] as const;
}

function loadThreatsFromExtension(): ThreatRecord[] {
  if (typeof window === "undefined") return [];
  try {
    const extData = localStorage.getItem("veritasai_scans");
    if (extData) {
      const scans = JSON.parse(extData) as Array<{
        url: string;
        domain: string;
        risk: string;
        score: number;
        trustScore: number;
        aiPrediction: string;
        mlRisk: string;
        time: number;
      }>;
      return scans.map((s, i) => ({
        id: `scan_${i}_${s.time}`,
        url: s.url,
        domain: s.domain,
        risk: (s.risk as any),
        score: s.score,
        trustScore: s.trustScore,
        confidence: 80 + Math.floor(Math.random() * 20),
        aiPrediction: s.aiPrediction,
        mlRisk: s.mlRisk,
        module: s.risk === "DANGEROUS" ? "Phishing URL" : s.risk === "SUSPICIOUS" ? "Scam Pattern" : "Trust Engine",
        reasons: [],
        severity: s.score >= 85 ? "Critical" : s.score >= 65 ? "High" : s.score >= 35 ? "Medium" : "Low",
        timestamp: s.time,
      }));
    }
  } catch {
    // Return empty array if parsing fails
  }
  return [];
}

export function useThreats() {
  return useVeritasStore<ThreatRecord[]>(THREATS_KEY, loadThreatsFromExtension);
}

export function useTrustedSites() {
  return useVeritasStore<TrustedSite[]>(TRUSTED_KEY, () => DEFAULT_TRUSTED);
}

export function useSettings() {
  return useVeritasStore<SecuritySettings>(SETTINGS_KEY, () => DEFAULT_SETTINGS);
}

export function clearAll() {
  if (typeof window === "undefined") return;
  localStorage.removeItem(THREATS_KEY);
  localStorage.removeItem(TRUSTED_KEY);
  localStorage.removeItem(SETTINGS_KEY);
  window.dispatchEvent(new CustomEvent("veritas:update", { detail: "*" }));
}

export function exportThreatsCSV(threats: ThreatRecord[]): string {
  const header = ["Website", "Risk", "Score", "TrustScore", "Module", "Timestamp"];
  const rows = threats.map((t) => [
    t.url,
    t.risk,
    t.score,
    t.trustScore,
    t.module,
    new Date(t.timestamp).toISOString(),
  ]);
  return [header, ...rows].map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
}

export function downloadCSV(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}