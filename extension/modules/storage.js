export const PERMANENT_SAFE = [
  "google.com",
  "youtube.com",
  "github.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "claude.ai",
  "chatgpt.com",
  "linkedin.com",
  "twitter.com",
  "instagram.com",
  "facebook.com",
  "whatsapp.com",
  "wikipedia.org",
  "stackoverflow.com",
  "netflix.com",
  "spotify.com",
  "reddit.com",
  "anthropic.com",
  "openai.com",
  "veritasai-shield.vercel.app",
];

export const getBaseDomain = (hostname) => {
  return hostname.replace(/^www\./, "").toLowerCase();
};

export const isPermanentSafe = (baseDomain) => {
  return PERMANENT_SAFE.some((safe) => baseDomain === safe || baseDomain.endsWith("." + safe));
};

const getCacheKey = (domain) => "vc_" + domain;

export const getCached = async (domain) => {
  try {
    const baseDomain = getBaseDomain(domain);
    if (isPermanentSafe(baseDomain)) {
      return {
        url: `https://${baseDomain}`,
        domain: baseDomain,
        risk: "SAFE",
        score: 0,
        trustScore: 100,
        aiPrediction: "Permanently trusted system domain.",
        mlRisk: "Safe",
        module: "Trust Engine",
        reasons: ["Verified permanent safe list entry"],
        time: Date.now(),
      };
    }

    const key = getCacheKey(domain);
    const data = await chrome.storage.local.get([key]);
    const entry = data[key];

    if (!entry) return null;

    const age = Date.now() - entry.timestamp;
    const risk = entry.result?.risk;

    const maxAge =
      risk === "SAFE"
        ? 24 * 60 * 60 * 1000 // SAFE sites: cache 24 hours (FIX A)
        : risk === "SUSPICIOUS"
          ? 30 * 60 * 1000 // SUSPICIOUS sites: cache 30 minutes (FIX A)
          : 5 * 60 * 1000; // DANGEROUS sites: cache 5 minutes (FIX A)

    if (age < maxAge) return entry.result;
    return null;
  } catch (e) {
    return null;
  }
};

export const saveCache = async (domain, result) => {
  try {
    const key = getCacheKey(domain);
    await chrome.storage.local.set({
      [key]: { result, timestamp: Date.now() },
    });
  } catch (e) {}
};

export const saveAndBroadcast = async (result) => {
  try {
    chrome.runtime
      .sendMessage({
        action: "updateBadge",
        risk: result.risk,
      })
      .catch(() => {});

    const { scanHistory = [] } = await chrome.storage.local.get(["scanHistory"]);
    const filtered = scanHistory.filter((s) => s.domain !== result.domain);
    const updated = [result, ...filtered].slice(0, 500);

    await chrome.storage.local.set({
      scanHistory: updated,
    });

    const isVeritasSite =
      window.location.href.includes("veritasai-shield.vercel.app") ||
      window.location.href.includes("localhost:") ||
      window.location.href.includes("127.0.0.1:");
    if (isVeritasSite) {
      localStorage.setItem("veritasai_scans", JSON.stringify(updated));
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: "veritasai_scans",
          newValue: JSON.stringify(updated),
        }),
      );
    }
  } catch (e) {
    console.warn("saveAndBroadcast error:", e.message);
  }
};

export const incrementVTCounter = async () => {
  try {
    const data = await chrome.storage.local.get(["vtCallsToday", "vtLastReset"]);
    const now = Date.now();
    const lastReset = data.vtLastReset || now;
    const hoursSinceReset = (now - lastReset) / (1000 * 60 * 60);

    if (hoursSinceReset >= 24) {
      await chrome.storage.local.set({
        vtCallsToday: 1,
        vtLastReset: now,
      });
    } else {
      await chrome.storage.local.set({
        vtCallsToday: (data.vtCallsToday || 0) + 1,
      });
    }
  } catch (e) {
    console.warn("Error incrementing VT counter:", e.message);
  }
};
