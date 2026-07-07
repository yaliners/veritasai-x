import { getVerdict, checkCloudfareDNS } from "./modules/apiClient.js";
import { runLocalModules } from "./modules/heuristics.js";
import {
  getCached,
  saveCache,
  saveAndBroadcast,
  isPermanentSafe,
  getBaseDomain,
} from "./modules/storage.js";
import { showAlert } from "./modules/alerts.js";

let lastScannedUrl = "";
let networkVerdictPromise = null;
let dnsPromise = null;
let startedUrl = "";

const startNetworkScans = (url) => {
  if (startedUrl === url) return;
  startedUrl = url;

  try {
    const host = new URL(url).hostname.toLowerCase();
    const base = getBaseDomain(host);

    const shouldBypass =
      host.includes("veritasai-shield.vercel.app") ||
      host.includes("localhost:") ||
      host.includes("127.0.0.1:") ||
      !url.startsWith("http") ||
      isPermanentSafe(base);

    if (!shouldBypass) {
      chrome.runtime.sendMessage({ action: "updateBadge", risk: "SCANNING" }).catch(() => {});
      networkVerdictPromise = getVerdict(url, base);
      dnsPromise = checkCloudfareDNS(base);
    } else {
      networkVerdictPromise = null;
      dnsPromise = null;
    }
  } catch (e) {
    networkVerdictPromise = null;
    dnsPromise = null;
  }
};

// Start parallel scans immediately at content script load (document_start)
try {
  startNetworkScans(window.location.href);
} catch (e) {
  console.warn("Failed to start initial background scans:", e);
}

const initScan = async () => {
  try {
    const fullUrl = window.location.href;
    if (fullUrl === lastScannedUrl) return;
    lastScannedUrl = fullUrl;

    const hostname = window.location.hostname.toLowerCase();
    const baseDomain = getBaseDomain(hostname);

    if (!fullUrl.startsWith("http")) return;

    // Check personal safe list before scanning
    const data = await chrome.storage.local.get(["settings", "personalSafeList"]);
    const settings = data.settings || {};
    const personalSafeList = data.personalSafeList || [];

    const controls = settings.controls || {
      autoScan: true,
      popupAlerts: true,
      overlayAlerts: true,
    };
    if (controls.autoScan === false) {
      chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" }).catch(() => {});
      return;
    }

    // If permanent safe or on the personal safe list, bypass scans
    if (isPermanentSafe(baseDomain) || personalSafeList.includes(baseDomain)) {
      const result = {
        url: fullUrl,
        domain: baseDomain,
        risk: "SAFE",
        score: 0,
        trustScore: 100,
        mlConfidence: "100%",
        module: "Trust Engine",
        aiPrediction: "Verified trusted domain",
        mlRisk: "Low",
        reasons: ["Verified trusted domain"],
        subScores: {
          google: 0,
          urlscan: 0,
          virustotal: 0,
          domainAge: 0,
          abuse: 0,
          dns: 0,
          local: 0,
        },
        time: Date.now(),
        cached: false,
        permanent: true,
      };
      await saveAndBroadcast(result);
      return;
    }

    const cached = await getCached(baseDomain);
    if (cached) {
      await saveAndBroadcast({
        ...cached,
        cached: true,
      });
      return;
    }

    chrome.runtime
      .sendMessage({
        action: "updateBadge",
        risk: "SCANNING",
      })
      .catch(() => {});

    // Ensure scans are started (handles dynamic SPA navigation/timing variations)
    startNetworkScans(fullUrl);

    // Call serverless proxy (awaiting pre-started promises)
    const proxyVerdict = networkVerdictPromise ? await networkVerdictPromise : null;
    const dns = dnsPromise ? await dnsPromise : { flag: 0, reason: null };
    const local = await runLocalModules(settings);

    let google = { score: 0, matched: false, reason: null };
    let urlscan = { score: 0, reason: null };
    let vt = { score: 0, reason: null, malicious: 0, total: 0 };
    let rdap = { flag: 0, ageDays: null, reason: null };
    let abuse = { score: 0, reason: null };

    if (proxyVerdict) {
      google = proxyVerdict.google || google;
      urlscan = proxyVerdict.urlscan || urlscan;
      vt = proxyVerdict.virustotal || vt;
      abuse = proxyVerdict.abuse || abuse;
      rdap = proxyVerdict.rdap || rdap;
    }

    const googleFlag = google.matched ? 100 : 0;
    const urlscanScore = urlscan.score || 0;
    const vtScore = vt.score || 0;
    const whoisFlag = rdap.flag || 0;
    const abuseScore = abuse.score || 0;
    const dnsFlag = dns.flag || 0;
    const localScore = local.localScore || 0;

    const apiScore = Math.round(
      googleFlag * 0.25 + urlscanScore * 0.25 + vtScore * 0.25 + abuseScore * 0.15 + dnsFlag * 0.1,
    );

    let threatScore = Math.min(apiScore + localScore + whoisFlag, 100);
    const trustScore = Math.max(0, 100 - threatScore);

    let risk = "SAFE";
    if (
      google.forceDANGEROUS ||
      urlscan.forceDANGEROUS ||
      vt.forceDANGEROUS ||
      abuse.forceDANGEROUS ||
      threatScore > 70
    ) {
      risk = "DANGEROUS";
    } else if (urlscan.forceSUSPICIOUS || abuse.forceSUSPICIOUS || threatScore > 35) {
      risk = "SUSPICIOUS";
    }

    const allReasons = [
      google.reason,
      urlscan.reason,
      vt.reason,
      rdap.reason,
      abuse.reason,
      dns.reason,
      ...local.reasons,
    ].filter(Boolean);

    if (!proxyVerdict) {
      allReasons.push("Local scan only — Proxy unavailable");
    }

    let module = "Trust Engine";
    if (google.matched) module = "Phishing URL";
    else if (vt.forceDANGEROUS) module = "Malware Detection";
    else if (urlscan.forceDANGEROUS) module = "Scam Pattern";
    else if (abuse.forceDANGEROUS) module = "IP Reputation";
    else if (rdap.flag > 0) module = "New Domain — High Risk";
    else if (dns.flag > 0) module = "DNS Anomaly";
    else if (localScore > 20) module = "Content NLP";

    const mlRisk = threatScore > 70 ? "High" : threatScore > 35 ? "Medium" : "Low";

    const result = {
      url: fullUrl,
      domain: baseDomain,
      risk,
      score: threatScore,
      trustScore,
      mlConfidence: threatScore + "%",
      module,
      aiPrediction:
        risk === "DANGEROUS"
          ? "Threat detected — do not proceed"
          : risk === "SUSPICIOUS"
            ? "Suspicious activity detected"
            : "No threats detected",
      mlRisk,
      reasons: allReasons.length > 0 ? allReasons : ["No threat signals detected"],
      subScores: {
        google: googleFlag,
        urlscan: urlscanScore,
        virustotal: vtScore,
        domainAge: whoisFlag,
        abuse: abuseScore,
        dns: dnsFlag,
        local: localScore,
      },
      time: Date.now(),
      cached: false,
    };

    await saveCache(baseDomain, result);
    await saveAndBroadcast(result);

    if (result.risk !== "SAFE" && controls.overlayAlerts) {
      showAlert(result, settings);
    }
  } catch (e) {
    console.warn("initScan error:", e.message);
    chrome.runtime
      .sendMessage({
        action: "updateBadge",
        risk: "SAFE",
      })
      .catch(() => {});
  }
};

// Listen for navigation scan triggers
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "scanPage") {
    initScan();
  }
});

// INITIALIZE AND DASHBOARD CHANNEL BINDINGS
const isVeritasSite =
  window.location.href.includes("veritasai-shield.vercel.app") ||
  window.location.href.includes("localhost:") ||
  window.location.href.includes("127.0.0.1:");

if (isVeritasSite) {
  document.documentElement.dataset.veritasShieldInstalled = "true";

  window.addEventListener("veritas_ping", () => {
    window.dispatchEvent(new CustomEvent("veritas_pong"));
  });
  window.dispatchEvent(new CustomEvent("veritas_pong"));

  chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
    localStorage.setItem("veritasai_scans", JSON.stringify(scanHistory));
    window.dispatchEvent(
      new StorageEvent("storage", {
        key: "veritasai_scans",
        newValue: JSON.stringify(scanHistory),
      }),
    );
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.scanHistory) {
      const updated = changes.scanHistory.newValue || [];
      localStorage.setItem("veritasai_scans", JSON.stringify(updated));
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: "veritasai_scans",
          newValue: JSON.stringify(updated),
        }),
      );
    }
  });

  window.addEventListener("veritas:update", (e) => {
    if (e.detail === "veritas:settings") {
      try {
        const localSettings = localStorage.getItem("veritas:settings");
        if (localSettings) {
          chrome.storage.local.set({ settings: JSON.parse(localSettings) });
        }
      } catch (err) {}
    }
    if (e.detail === "veritas:trusted") {
      try {
        const localTrusted = localStorage.getItem("veritas:trusted");
        if (localTrusted) {
          const parsed = JSON.parse(localTrusted);
          const domains = parsed.map((x) => x.domain.toLowerCase());
          chrome.storage.local.set({ trustedDomains: domains });
        }
      } catch (err) {}
    }
  });
} else {
  if (document.readyState === "complete" || document.readyState === "interactive") {
    initScan();
  } else {
    window.addEventListener("DOMContentLoaded", initScan);
  }
}
