import type { ThreatRecord, TrustedSite, DetectionModule, Risk } from "./types";

const SAMPLE_THREATS: Array<Partial<ThreatRecord> & { url: string; module: DetectionModule; risk: Risk; reasons: string[] }> = [
  { url: "https://secure-paypa1-login.com/verify", module: "Phishing URL", risk: "DANGEROUS", reasons: ["Typosquatted domain detected", "Password field on unverified domain", "Suspicious keyword: verify"] },
  { url: "https://crypto-doubler-rewards.net/claim", module: "Scam Pattern", risk: "DANGEROUS", reasons: ["Crypto giveaway pattern", "Unrealistic ROI promise", "Wallet address request detected"] },
  { url: "https://amaz0n-orders-support.help/login", module: "Phishing URL", risk: "DANGEROUS", reasons: ["Brand impersonation: Amazon", "Homoglyph attack on domain", "Login form on lookalike domain"] },
  { url: "https://chatgpt-pro-free-tokens.io", module: "AI Content", risk: "SUSPICIOUS", reasons: ["AI-generated marketing copy", "Manipulative urgency cues", "Implausible offer"] },
  { url: "https://flash-sale-72h-ending.shop/checkout", module: "Dark Pattern", risk: "SUSPICIOUS", reasons: ["Fake countdown timer", "Forced scarcity claims", "Hidden subscription terms"] },
  { url: "https://github.com", module: "Trust Engine", risk: "TRUSTED", reasons: ["High domain reputation", "Valid EV SSL certificate", "Whitelisted developer platform"] },
  { url: "https://google.com", module: "Trust Engine", risk: "TRUSTED", reasons: ["Verified root domain", "Strong reputation history"] },
  { url: "https://urgent-tax-refund-irs.gov.help", module: "Phishing URL", risk: "DANGEROUS", reasons: ["Government brand impersonation", "Urgency phishing keywords", "Suspicious TLD chain"] },
  { url: "https://win-iphone15-survey.click", module: "Scam Pattern", risk: "DANGEROUS", reasons: ["Fake giveaway pattern", "Survey-to-prize funnel", "Unverified affiliate redirect"] },
  { url: "https://meta-business-suspended-appeal.com", module: "Phishing URL", risk: "DANGEROUS", reasons: ["Account suspension lure", "Credential harvesting form", "No SSL EV certificate"] },
  { url: "https://news.ycombinator.com", module: "Trust Engine", risk: "SAFE", reasons: ["Established domain", "No malicious indicators"] },
  { url: "https://stripe.com", module: "Trust Engine", risk: "TRUSTED", reasons: ["Verified payments processor", "Strict CSP headers"] },
  { url: "https://free-netflix-premium-2026.online", module: "Scam Pattern", risk: "DANGEROUS", reasons: ["Pirated content lure", "Credit card phishing form"] },
  { url: "https://limited-offer-act-now-deal.store", module: "Dark Pattern", risk: "SUSPICIOUS", reasons: ["Manipulative countdown", "Misleading CTA labels"] },
  { url: "https://wikipedia.org", module: "Trust Engine", risk: "TRUSTED", reasons: ["Encyclopedia source", "High trust reputation"] },
  { url: "https://invoice-payment-required-urgent.biz", module: "Scam Pattern", risk: "DANGEROUS", reasons: ["BEC invoice fraud pattern", "Wire transfer request", "Spoofed sender"] },
  { url: "https://openai.com", module: "Trust Engine", risk: "TRUSTED", reasons: ["Verified vendor"] },
  { url: "https://reset-your-password-bank.support", module: "Phishing URL", risk: "DANGEROUS", reasons: ["Bank impersonation", "Password reset social engineering"] },
  { url: "https://nft-mint-airdrop-claim.xyz", module: "Scam Pattern", risk: "DANGEROUS", reasons: ["NFT airdrop scam pattern", "Wallet-drainer signature request"] },
  { url: "https://medium.com", module: "Trust Engine", risk: "SAFE", reasons: ["Established publication platform"] },
];

const SEVERITIES = ["Low", "Medium", "High", "Critical"] as const;

function severityFromScore(score: number): ThreatRecord["severity"] {
  if (score >= 85) return "Critical";
  if (score >= 65) return "High";
  if (score >= 35) return "Medium";
  return "Low";
}

function scoresForRisk(risk: Risk) {
  switch (risk) {
    case "DANGEROUS":
      return { score: 70 + Math.floor(Math.random() * 30), trust: Math.floor(Math.random() * 20) };
    case "SUSPICIOUS":
      return { score: 40 + Math.floor(Math.random() * 25), trust: 25 + Math.floor(Math.random() * 25) };
    case "SAFE":
      return { score: 5 + Math.floor(Math.random() * 15), trust: 70 + Math.floor(Math.random() * 15) };
    case "TRUSTED":
      return { score: 0, trust: 95 + Math.floor(Math.random() * 5) };
  }
}

export function generateThreats(): ThreatRecord[] {
  const now = Date.now();
  return SAMPLE_THREATS.map((s, i) => {
    const { score, trust } = scoresForRisk(s.risk);
    const domain = new URL(s.url).hostname;
    return {
      id: `thr_${i}_${Math.random().toString(36).slice(2, 8)}`,
      url: s.url,
      domain,
      risk: s.risk,
      score,
      trustScore: trust,
      confidence: 75 + Math.floor(Math.random() * 24),
      aiPrediction: s.risk === "DANGEROUS" ? "Malicious" : s.risk === "SUSPICIOUS" ? "Suspicious" : "Benign",
      mlRisk: `${(score / 100).toFixed(2)}`,
      module: s.module,
      reasons: s.reasons,
      severity: severityFromScore(score),
      timestamp: now - i * 1000 * 60 * Math.floor(7 + Math.random() * 60),
    };
  });
}

export const DEFAULT_TRUSTED: TrustedSite[] = [
  { id: "t1", domain: "github.com", category: "Developer Tools", trustLevel: "Enterprise", addedAt: Date.now() - 86400000 * 30 },
  { id: "t2", domain: "google.com", category: "Search", trustLevel: "Enterprise", addedAt: Date.now() - 86400000 * 60 },
  { id: "t3", domain: "stripe.com", category: "Payments", trustLevel: "Enterprise", addedAt: Date.now() - 86400000 * 14 },
  { id: "t4", domain: "openai.com", category: "AI Vendor", trustLevel: "High", addedAt: Date.now() - 86400000 * 10 },
  { id: "t5", domain: "wikipedia.org", category: "Reference", trustLevel: "High", addedAt: Date.now() - 86400000 * 90 },
];