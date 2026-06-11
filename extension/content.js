(function () {
  const isVeritasSite = window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:");

  if (isVeritasSite) {
    document.documentElement.dataset.veritasShieldInstalled = "true";
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      localStorage.setItem("veritasai_scans", JSON.stringify(scanHistory));
      window.dispatchEvent(new StorageEvent("storage", { key: "veritasai_scans", newValue: JSON.stringify(scanHistory) }));
    });

    // Sync settings from webpage to extension
    try {
      const localSettings = localStorage.getItem("veritas:settings");
      if (localSettings) {
        const parsed = JSON.parse(localSettings);
        chrome.storage.local.set({ settings: parsed });
      }
    } catch (e) {
      console.error("VeritasShield: Settings sync failed", e);
    }

    // Sync trusted domains from webpage to extension
    try {
      const localTrusted = localStorage.getItem("veritas:trusted");
      if (localTrusted) {
        const parsed = JSON.parse(localTrusted);
        const domains = parsed.map(x => x.domain.toLowerCase());
        chrome.storage.local.set({ trustedDomains: domains });
      }
    } catch (e) {
      console.error("VeritasShield: Trusted domains sync failed", e);
    }
    return;
  }

  const url = location.href;
  const PHISHING = ["login", "verify", "bank", "password", "otp", "suspended"];
  const SCAM = ["giveaway", "claim reward", "send bitcoin", "wire transfer", "gift card"];
  const DARK = ["limited-time", "act-now", "ends-in", "only-today", "flash-sale"];

  // Default configuration
  const DEFAULT_SETTINGS = {
    modules: { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false },
    controls: { autoScan: true, popupAlerts: true, overlayAlerts: true },
  };

  // Read settings and execute edge scans accordingly
  chrome.storage.local.get(["settings", "trustedDomains"], ({ settings = DEFAULT_SETTINGS, trustedDomains = [] }) => {
    const modules = settings?.modules || DEFAULT_SETTINGS.modules;
    const controls = settings?.controls || DEFAULT_SETTINGS.controls;

    // 1. Respect Auto Scan (System Control)
    if (!controls.autoScan) {
      return; 
    }

    // 2. Bypass scanning for whitelisted trusted domains
    let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch {}
    const isWhitelisted = trustedDomains.some((d) => host === d || host.endsWith("." + d));
    if (isWhitelisted) {
      return; 
    }

    const text = document.body ? document.body.innerText.toLowerCase() : "";
    let score = 0;
    const reasons = [];

    // 2. Respect Phishing Detector (Security Module)
    if (modules.phishing) {
      PHISHING.forEach((k) => { 
        if (url.toLowerCase().includes(k)) { 
          score += 20; 
          reasons.push("Phishing keyword: " + k); 
        } 
      });
      if (document.querySelector('input[type="password"]') && !location.protocol.includes("https")) { 
        score += 30; 
        reasons.push("Password field on insecure page"); 
      }
    }

    // 3. Respect Scam Detector (Security Module)
    if (modules.scam) {
      SCAM.forEach((k) => { 
        if (text.includes(k)) { 
          score += 25; 
          reasons.push("Scam phrase: " + k); 
        } 
      });
    }

    // 4. Respect Dark Pattern Detector (Security Module)
    if (modules.darkPattern) {
      DARK.forEach((k) => {
        if (text.includes(k)) {
          score += 15;
          reasons.push("Urgency dark pattern: " + k);
        }
      });
    }

    // Heuristics mapping for visual feedback in score
    const scanResult = {
      url: url,
      domain: new URL(url).hostname,
      risk: score >= 85 ? "DANGEROUS" : score >= 50 ? "SUSPICIOUS" : "SAFE",
      score: Math.min(100, score),
      trustScore: Math.max(0, 100 - score),
      aiPrediction: score >= 85 ? "Malicious" : score >= 50 ? "Suspicious" : "Benign",
      mlRisk: (Math.min(100, score) / 100).toFixed(2),
      time: Date.now(),
    };

    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      const updated = [scanResult, ...scanHistory].slice(0, 50);
      chrome.storage.local.set({ scanHistory: updated });
      localStorage.setItem("veritasai_scans", JSON.stringify(updated));
    });

    // 5. Respect Overlay Alerts (System Control)
    if (score >= 65 && controls.overlayAlerts) {
      showOverlay(score, reasons);
    }
  });

  function showOverlay(score, reasons) {
    if (document.getElementById("veritas-overlay")) return;
    const el = document.createElement("div");
    el.id = "veritas-overlay";
    el.innerHTML = '<div style="position:fixed;inset:0;background:rgba(2,8,23,0.85);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;"><div style="max-width:480px;background:#081225;border:1px solid rgba(239,68,68,0.5);border-radius:16px;padding:24px;color:#e6edf7;box-shadow:0 20px 60px rgba(0,0,0,0.6);"><p style="font-size:11px;letter-spacing:0.2em;color:#ef4444;font-weight:700;">VERITAS SHIELD ALERT</p><h2 style="font-size:22px;margin:6px 0 4px;">&#9888; Threat Detected</h2><p style="font-size:13px;color:#9aa8c2;margin-bottom:16px;">This page exhibits malicious patterns. Risk Score: <b style="color:#ef4444">' + score + '</b></p><ul style="margin:0 0 18px 16px;font-size:12px;line-height:1.7;">' + reasons.map(function(r){return "<li>"+r+"</li>";}).join("") + '</ul><div style="display:flex;gap:8px;"><button id="vleave" style="flex:1;padding:10px;border:none;border-radius:10px;background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;font-weight:700;cursor:pointer;">Leave Site</button><button id="vcont" style="flex:1;padding:10px;border:1px solid rgba(154,168,194,0.4);border-radius:10px;background:transparent;color:#9aa8c2;font-weight:600;cursor:pointer;">Continue Anyway</button></div></div></div>';
    document.documentElement.appendChild(el);
    el.querySelector("#vleave").onclick = function() { history.back(); };
    el.querySelector("#vcont").onclick = function() { el.remove(); };
  }
})();