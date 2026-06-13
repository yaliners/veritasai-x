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

    // Listen for real-time settings and trusted updates from the web page
    window.addEventListener("veritas:update", (e) => {
      if (e.detail === "veritas:settings") {
        try {
          const localSettings = localStorage.getItem("veritas:settings");
          if (localSettings) {
            chrome.storage.local.set({ settings: JSON.parse(localSettings) });
          }
        } catch (err) {
          console.error("VeritasShield: Real-time settings sync failed", err);
        }
      }
      if (e.detail === "veritas:trusted") {
        try {
          const localTrusted = localStorage.getItem("veritas:trusted");
          if (localTrusted) {
            const parsed = JSON.parse(localTrusted);
            const domains = parsed.map(x => x.domain.toLowerCase());
            chrome.storage.local.set({ trustedDomains: domains });
          }
        } catch (err) {
          console.error("VeritasShield: Real-time trusted domains sync failed", err);
        }
      }
    });

    return;
  }

  async function initScan() {
    const url = location.href;

    // Default configuration
    const DEFAULT_SETTINGS = {
      modules: { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false },
      controls: { autoScan: true, popupAlerts: true, overlayAlerts: true },
      apiKeys: { googleSafeBrowsing: "", ipQualityScore: "", virusTotal: "", whoisXml: "" }
    };

    chrome.storage.local.get(["settings", "trustedDomains"], async ({ settings = DEFAULT_SETTINGS, trustedDomains = [] }) => {
      const modules = settings?.modules || DEFAULT_SETTINGS.modules;
      const controls = settings?.controls || DEFAULT_SETTINGS.controls;
      const apiKeys = settings?.apiKeys || DEFAULT_SETTINGS.apiKeys;

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

      // First check blocklists
      const isDangerousDomain = DANGEROUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
      const isSuspiciousDomain = SUSPICIOUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));

      if (isDangerousDomain) {
        const scanResult = {
          url: url,
          domain: host,
          risk: "DANGEROUS",
          score: 95,
          trustScore: 5,
          aiPrediction: "Malicious",
          mlRisk: "0.95",
          module: "Blocklist",
          time: Date.now(),
          reasons: ["Blacklisted dangerous domain"],
          modules: { phishing: 95, scam: 20, ai: 85, dark: 10, trust: 5 },
          conf: 98
        };
        saveScanResult(scanResult);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "DANGEROUS" });
        if (controls.overlayAlerts) {
          showOverlay(95, ["Blacklisted dangerous domain"]);
        }
        return;
      }

      if (isSuspiciousDomain) {
        const scanResult = {
          url: url,
          domain: host,
          risk: "SUSPICIOUS",
          score: 65,
          trustScore: 35,
          aiPrediction: "Suspicious",
          mlRisk: "0.65",
          module: "Blocklist",
          time: Date.now(),
          reasons: ["Blacklisted suspicious domain"],
          modules: { phishing: 65, scam: 15, ai: 50, dark: 10, trust: 35 },
          conf: 92
        };
        saveScanResult(scanResult);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "SUSPICIOUS" });
        if (controls.overlayAlerts) {
          showOverlay(65, ["Blacklisted suspicious domain"]);
        }
        return;
      }

      // Initialize scores
      let googleFlag = 0;
      let ipqsScore = 0;
      let vtScore = 0;
      let localModuleScore = 0;
      
      let M5_score = 0;
      let M6_score = 0;
      let M7_score = 0;

      let gsbFired = false;
      let vtFired = false;
      let whoisFired = false;
      
      let ipqsForceDangerous = false;
      let ipqsForceSuspicious = false;
      let vtForceDangerous = false;

      const reasons = [];

      // API 1: Google Safe Browsing
      if (apiKeys.googleSafeBrowsing) {
        try {
          const gsbUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKeys.googleSafeBrowsing}`;
          const gsbRes = await fetch(gsbUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              client: { clientId: "veritasai", clientVersion: "1.0" },
              threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: url }]
              }
            })
          });
          const gsbData = await gsbRes.json();
          if (gsbData.matches && gsbData.matches.length > 0) {
            googleFlag = 100;
            gsbFired = true;
            reasons.push("Google Safe Browsing: URL flagged as " + gsbData.matches[0].threatType);
          }
        } catch (e) {
          console.error("VeritasShield: GSB API failed", e);
        }
      }

      // API 2: IPQualityScore
      if (apiKeys.ipQualityScore) {
        try {
          const ipqsUrl = `https://ipqualityscore.com/api/json/url/${apiKeys.ipQualityScore}/${encodeURIComponent(url)}`;
          const ipqsRes = await fetch(ipqsUrl);
          const ipqsData = await ipqsRes.json();
          if (ipqsData.success) {
            const fraudScore = ipqsData.fraud_score || 0;
            ipqsScore = fraudScore;
            if (fraudScore > 75) ipqsForceDangerous = true;
            else if (fraudScore > 40) ipqsForceSuspicious = true;

            if (ipqsData.phishing === true || ipqsData.malware === true) {
              ipqsForceDangerous = true;
              ipqsScore = 100;
            }
            reasons.push("IPQualityScore: Fraud score " + fraudScore + " (Phishing: " + !!ipqsData.phishing + ", Malware: " + !!ipqsData.malware + ")");
          }
        } catch (e) {
          console.error("VeritasShield: IPQS API failed", e);
        }
      }

      // API 3: VirusTotal
      if (apiKeys.virusTotal) {
        try {
          // Calculate unpadded Base64 URL ID
          let vtId = "";
          try {
            const utf8Bytes = new TextEncoder().encode(url);
            const binaryString = Array.from(utf8Bytes, byte => String.fromCharCode(byte)).join('');
            vtId = btoa(binaryString).replace(/=/g, "");
          } catch (e) {
            vtId = btoa(url).replace(/=/g, "");
          }

          // Try GET to check if report is already cached
          let vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${vtId}`, {
            headers: { "x-apikey": apiKeys.virusTotal }
          });

          let positives = 0;
          if (vtRes.status === 200) {
            const vtData = await vtRes.json();
            positives = vtData.data?.attributes?.last_analysis_stats?.malicious || 0;
          } else if (vtRes.status === 404) {
            // Fallback: Submit scan using POST
            const scanRes = await fetch("https://www.virustotal.com/api/v3/urls", {
              method: "POST",
              headers: {
                "x-apikey": apiKeys.virusTotal,
                "Content-Type": "application/x-www-form-urlencoded"
              },
              body: `url=${encodeURIComponent(url)}`
            });
            if (scanRes.ok) {
              const scanData = await scanRes.json();
              const analysisId = scanData.data?.id;
              if (analysisId) {
                // Poll/Retrieve the analysis results
                const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                  headers: { "x-apikey": apiKeys.virusTotal }
                });
                if (analysisRes.ok) {
                  const analysisData = await analysisRes.json();
                  positives = analysisData.data?.attributes?.stats?.malicious || 0;
                }
              }
            }
          }

          if (positives > 3) {
            vtScore = 100;
            vtForceDangerous = true;
            vtFired = true;
            reasons.push("VirusTotal: URL flagged as malicious by " + positives + " engines");
          }
        } catch (e) {
          console.error("VeritasShield: VirusTotal API failed", e);
        }
      }

      // API 4: Domain Age Check (WhoisXMLAPI)
      let domainAgeFlag = 0;
      if (apiKeys.whoisXml) {
        try {
          const whoisRes = await fetch(`https://domain-age-checker.whoisxmlapi.com/api/v1?apiKey=${apiKeys.whoisXml}&domainName=${host}`);
          const whoisData = await whoisRes.json();
          let ageInDays = whoisData.domainAge || whoisData.estimatedDomainAge || whoisData.WhoisRecord?.estimatedDomainAge;
          const createdDateStr = whoisData.createdDate || whoisData.WhoisRecord?.createdDate;
          if (ageInDays === undefined && createdDateStr) {
            const createdTime = Date.parse(createdDateStr);
            if (!isNaN(createdTime)) {
              ageInDays = Math.floor((Date.now() - createdTime) / (1000 * 60 * 60 * 24));
            }
          }
          if (ageInDays !== undefined && ageInDays < 30) {
            domainAgeFlag = 30;
            whoisFired = true;
            reasons.push("Domain age: Registered less than 30 days ago (" + ageInDays + " days)");
          }
        } catch (e) {
          console.error("VeritasShield: WhoisXMLAPI failed", e);
        }
      }

      // Local Module 5: Dark Pattern
      if (modules.darkPattern) {
        // Pre-ticked checkboxes
        const preTicked = document.querySelectorAll('input[type="checkbox"]:checked').length > 0;
        if (preTicked) {
          M5_score += 15;
          reasons.push("Dark Pattern: Pre-ticked checkboxes detected");
        }

        // Hidden opt-outs
        let hasHiddenOptOut = false;
        try {
          const hiddenEl = Array.from(document.querySelectorAll('*')).find(el => {
            const style = window.getComputedStyle(el);
            const isHidden = style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0';
            if (isHidden) {
              const text = (el.innerText || el.textContent || "").toLowerCase();
              return text.includes("opt-out") || text.includes("optout") || text.includes("unsubscribe");
            }
            return false;
          });
          if (hiddenEl) {
            hasHiddenOptOut = true;
            M5_score += 15;
            reasons.push("Dark Pattern: Hidden opt-out/unsubscribe options found");
          }
        } catch (e) {}

        // Countdown timers
        let hasTimer = false;
        try {
          const timerRegex = /\b\d+\s*(?:sec|min|hour|day|second|minute)/i;
          const timerEl = Array.from(document.querySelectorAll('div, span, p, label, section, header')).find(el => {
            const text = (el.innerText || el.textContent || "").toLowerCase();
            const hasTimePattern = timerRegex.test(text);
            const hasTimerClassOrId = /\btimer\b|\bcount\b|\bexpiry\b/i.test(el.className + " " + el.id);
            return hasTimePattern && hasTimerClassOrId;
          });
          if (timerEl) {
            hasTimer = true;
            M5_score += 15;
            reasons.push("Dark Pattern: Urgent countdown timers detected");
          }
        } catch (e) {}
      }

      // Local Module 6: Insecure Connection SSL Check
      const isHttp = location.protocol === "http:";
      if (isHttp) {
        M6_score = 25;
        reasons.push("Insecure connection: Page does not use SSL (HTTP)");
      }

      // Local Module 7: Content NLP scam keywords
      if (modules.scam || modules.aiContent) {
        const text = (document.body ? document.body.innerText : "").toLowerCase();
        const scamPhrases = ["you have won", "claim now", "verify account", "urgent", "act immediately", "limited time"];
        scamPhrases.forEach(phrase => {
          if (text.includes(phrase)) {
            M7_score += 10;
            reasons.push("Content NLP: Detected scam keyword/phrase '" + phrase + "'");
          }
        });
      }

      localModuleScore = M5_score + M6_score + M7_score;

      // Local Module 8: Trust Engine (composite calculation)
      const baseScore = (googleFlag * 0.25 + ipqsScore * 0.40 + vtScore * 0.35);
      
      // Calculate final composite score
      let threatScore = baseScore + localModuleScore;
      if (gsbFired) {
        threatScore += 40;
      }
      if (whoisFired) {
        threatScore += 30;
      }

      // Cap final threatScore at 100
      threatScore = Math.min(100, threatScore);

      // Determine final risk rating and enforce thresholds
      let risk = "SAFE";
      if (threatScore > 70 || ipqsForceDangerous || vtForceDangerous) {
        risk = "DANGEROUS";
        threatScore = Math.max(75, threatScore);
      } else if (threatScore > 35 || ipqsForceSuspicious) {
        risk = "SUSPICIOUS";
        threatScore = Math.max(40, threatScore);
      }

      const trustScore = Math.max(0, 100 - threatScore);

      // Map dynamic module
      let moduleName = "Trust Engine";
      if (isDangerousDomain || isSuspiciousDomain) {
        moduleName = "Blocklist";
      } else if (gsbFired) {
        moduleName = "Phishing URL";
      } else if (vtFired) {
        moduleName = "Malware Detection";
      } else if (whoisFired) {
        moduleName = "New Domain — High Risk";
      } else if (M6_score > 0) {
        moduleName = "SSL Check";
      } else if (M7_score > 0) {
        moduleName = "Content NLP";
      } else if (M5_score > 0) {
        moduleName = "Dark Pattern";
      }

      if (reasons.length === 0) {
        reasons.push("No malicious indicators detected");
      }

      const scanResult = {
        url: url,
        domain: host,
        risk: risk,
        score: Math.round(threatScore),
        trustScore: Math.round(trustScore),
        aiPrediction: risk === "DANGEROUS" ? "Malicious" : risk === "SUSPICIOUS" ? "Suspicious" : "Benign",
        mlRisk: (threatScore / 100).toFixed(2),
        module: moduleName,
        time: Date.now(),
        reasons: reasons,
        modules: {
          phishing: gsbFired ? 100 : (risk === "DANGEROUS" ? 90 : risk === "SUSPICIOUS" ? 50 : 10),
          scam: M7_score > 0 ? 80 : (risk === "DANGEROUS" ? 60 : 15),
          ai: Math.round(threatScore * 0.8),
          dark: M5_score > 0 ? 80 : 10,
          trust: Math.round(trustScore)
        },
        conf: Math.round(threatScore)
      };

      saveScanResult(scanResult);

      // Send update message to background badge
      chrome.runtime.sendMessage({ action: "updateBadge", risk: risk });

      // Respect Overlay Alerts
      if (risk !== "SAFE" && controls.overlayAlerts) {
        showOverlay(Math.round(threatScore), reasons);
      }
    });
  }

  function saveScanResult(scanResult) {
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      // Remove duplicate for same url
      const filtered = scanHistory.filter(h => h.url !== scanResult.url);
      const updated = [scanResult, ...filtered].slice(0, 50);
      chrome.storage.local.set({ scanHistory: updated });
      localStorage.setItem("veritasai_scans", JSON.stringify(updated));
      window.dispatchEvent(new StorageEvent("storage", { key: "veritasai_scans", newValue: JSON.stringify(updated) }));
    });
  }

  function showOverlay(score, reasons) {
    if (document.getElementById("veritas-overlay")) return;
    const el = document.createElement("div");
    el.id = "veritas-overlay";
    el.innerHTML = '<div style="position:fixed;inset:0;background:rgba(2,8,23,0.85);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;"><div style="max-width:480px;background:#081225;border:1px solid rgba(239,68,68,0.5);border-radius:16px;padding:24px;color:#e6edf7;box-shadow:0 20px 60px rgba(0,0,0,0.6);"><p style="font-size:11px;letter-spacing:0.2em;color:#ef4444;font-weight:700;">VERITAS SHIELD ALERT</p><h2 style="font-size:22px;margin:6px 0 4px;">&#9888; Threat Detected</h2><p style="font-size:13px;color:#9aa8c2;margin-bottom:16px;">This page exhibits malicious patterns. Risk Score: <b style="color:#ef4444">' + score + '</b></p><ul style="margin:0 0 18px 16px;font-size:12px;line-height:1.7;">' + reasons.map(function(r){return "<li>"+r+"</li>";}).join("") + '</ul><div style="display:flex;gap:8px;"><button id="vleave" style="flex:1;padding:10px;border:none;border-radius:10px;background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;font-weight:700;cursor:pointer;">Leave Site</button><button id="vcont" style="flex:1;padding:10px;border:1px solid rgba(154,168,194,0.4);border-radius:10px;background:transparent;color:#9aa8c2;font-weight:600;cursor:pointer;">Continue Anyway</button></div></div></div>';
    document.documentElement.appendChild(el);
    el.querySelector("#vleave").onclick = function() { history.back(); };
    el.querySelector("#vcont").onclick = function() { el.remove(); };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initScan);
  } else {
    initScan();
  }
})();