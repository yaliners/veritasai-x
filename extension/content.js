(function () {
  const DANGEROUS_BLOCKLIST = [
    "phishing.testing.google.test",
    "malware.testing.google.test",
    "testphp.vulnweb.com",
    "testfire.net",
    "zero.webappsecurity.com",
    "secure-paypal-login.net",
    "paypa1.com",
    "crypto-doubler.xyz",
    "freerobux-generator.xyz",
    "win-prize-now.click"
  ];

  const SUSPICIOUS_BLOCKLIST = [
    "netmirror.org",
    "crackingpatching.com",
    "softonic.com",
    "opensubtitles.org",
    "fmovies.to"
  ];

  const isVeritasSite = window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:");

  if (isVeritasSite) {
    document.documentElement.dataset.veritasShieldInstalled = "true";

    // Responsive live ping listener for real-time status checks
    window.addEventListener("veritas_ping", () => {
      window.dispatchEvent(new CustomEvent("veritas_pong"));
    });
    // Trigger immediate pong on script load
    window.dispatchEvent(new CustomEvent("veritas_pong"));

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

  function initScan() {
    const url = location.href;
    const PHISHING = ["login", "verify", "bank", "account", "password", "otp", "reset-password", "security-alert", "confirm-identity", "suspended"];
    const SCAM = ["free-money", "lottery", "claim", "giveaway", "double-your", "wire-transfer", "send-bitcoin", "guarantee", "urgent-payment", "gift-card"];
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

      let score = 0;
      const reasons = [];
      let moduleName = "Trust Engine";
      
      const lowerUrl = url.toLowerCase();
      const pageTitle = document.title ? document.title.toLowerCase() : "";

      const DANGEROUS_KEYWORDS = ["phishing", "malware", "trojan", "ransomware", "keylogger", "exploit", "payload", "botnet"];
      const SUSPICIOUS_KEYWORDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".click", ".top", ".gq", "free-", "win-", "claim-", "crypto-", "login-secure", "verify-account"];

      const isDangerousDomain = DANGEROUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
      const isSuspiciousDomain = SUSPICIOUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
      const hasDangerousKeyword = DANGEROUS_KEYWORDS.some(k => lowerUrl.includes(k) || pageTitle.includes(k));
      const hasSuspiciousKeyword = SUSPICIOUS_KEYWORDS.some(k => lowerUrl.includes(k)) || /\d{3,}/.test(host);

      if (isDangerousDomain) {
        score = 95;
        reasons.push("Blacklisted dangerous domain");
        moduleName = "Blocklist";
      } else if (isSuspiciousDomain) {
        score = 65;
        reasons.push("Blacklisted suspicious domain");
        moduleName = "Blocklist";
      } else if (hasDangerousKeyword) {
        score = 95;
        reasons.push("Dangerous keyword detected in URL or page title");
        moduleName = "Heuristics";
      } else if (hasSuspiciousKeyword) {
        score = 65;
        reasons.push("Suspicious pattern or TLD detected in URL");
        moduleName = "Heuristics";
      } else {
        const text = document.body ? document.body.innerText.toLowerCase() : "";

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
        
        moduleName = score >= 85 ? "Phishing URL" : score >= 50 ? "Scam Pattern" : "Trust Engine";
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
        module: moduleName,
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
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initScan);
  } else {
    initScan();
  }
})();