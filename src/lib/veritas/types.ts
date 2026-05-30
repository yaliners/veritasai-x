export type Risk = "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "TRUSTED";
export type DetectionModule =
  | "Phishing URL"
  | "Scam Pattern"
  | "AI Content"
  | "Dark Pattern"
  | "Trust Engine";

export interface ThreatRecord {
  id: string;
  url: string;
  domain: string;
  risk: Risk;
  score: number; // 0-100 threat score
  trustScore: number; // 0-100
  confidence: number; // 0-100
  aiPrediction: string;
  mlRisk: string;
  module: DetectionModule;
  reasons: string[];
  severity: "Low" | "Medium" | "High" | "Critical";
  timestamp: number;
}

export interface TrustedSite {
  id: string;
  domain: string;
  category: string;
  trustLevel: "Standard" | "High" | "Enterprise";
  addedAt: number;
}

export interface SecuritySettings {
  modules: {
    phishing: boolean;
    scam: boolean;
    aiContent: boolean;
    darkPattern: boolean;
    qrDetector: boolean;
    voiceClone: boolean;
  };
  controls: {
    autoScan: boolean;
    popupAlerts: boolean;
    overlayAlerts: boolean;
  };
}