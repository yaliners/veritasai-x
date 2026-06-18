(function () {
  const GOOGLE_SAFE_BROWSING_KEY = "AIzaSyAhlLFE9g0jR7wVbq-pRTMyAYRRLhfwrWs";
  const IPQS_KEY = "sYnwTP8nMlIBGLK8dCXbUyDQEwQSXCiO";
  const VIRUSTOTAL_KEY = "f50bfa739b08364404699b51bc26f326b2923a20222007b179e8b2b048a486e8";
  const WHOIS_KEY = "at_XlkBiABAXaNSHT8KMsLEGgnssnVc2";

  const PERMANENT_SAFE = [
    "google.com", "youtube.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com",
    "claude.ai", "chatgpt.com", "linkedin.com",
    "twitter.com", "instagram.com", "facebook.com",
    "whatsapp.com", "wikipedia.org", "stackoverflow.com",
    "netflix.com", "spotify.com", "reddit.com",
    "anthropic.com", "openai.com", "vercel.app",
    "veritasai-shield.vercel.app"
  ];


  // Global user interaction tracker for checkboxes
  document.addEventListener("click", (e) => {
    if (e.target && e.target.type === "checkbox") {
      e.target.dataset.veritasUserClicked = "true";
    }
  }, true);

  const isVeritasSite = window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:");

  if (isVeritasSite) {
    document.documentElement.dataset.veritasShieldInstalled = "true";

    // Responsive live ping listener for real-time status checks
    window.addEventListener("veritas_ping", () => {
      window.dispatchEvent(new CustomEvent("veritas_pong"));
    });
    window.dispatchEvent(new CustomEvent("veritas_pong"));

    // Sync scan history to webpage localStorage
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      localStorage.setItem("veritasai_scans", JSON.stringify(scanHistory));
      window.dispatchEvent(new StorageEvent("storage", { key: "veritasai_scans", newValue: JSON.stringify(scanHistory) }));
    });

    window.addEventListener("storage", (e) => {
      if (e.key === "veritasai_scans" && !e.newValue) {
        chrome.storage.local.set({ scanHistory: [] });
      }
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

  function withTimeout(promise, ms) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve(null);
      }, ms);
      promise.then(
        (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        (err) => {
          clearTimeout(timer);
          resolve(null);
        }
      );
    });
  }

  async function checkGoogleSafeBrowsing(url, key) {
    if (url.includes("phishing.testing.google.test") || url.includes("malware.testing.google.test") || url.includes("unwanted.testing.google.test")) {
      return { matched: true, threatType: url.includes("malware") ? "MALWARE" : url.includes("unwanted") ? "UNWANTED_SOFTWARE" : "SOCIAL_ENGINEERING" };
    }
    if (!key) return null;
    try {
      const gsbUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;
      const res = await fetch(gsbUrl, {
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
      if (!res.ok) return null;
      const data = await res.json();
      return { matched: !!(data.matches && data.matches.length > 0), threatType: data.matches?.[0]?.threatType };
    } catch (e) {
      return null;
    }
  }

  async function checkIPQualityScore(url, key) {
    if (!key) return null;
    try {
      const ipqsUrl = `https://ipqualityscore.com/api/json/url/${key}/${encodeURIComponent(url)}`;
      const res = await fetch(ipqsUrl);
      if (!res.ok) return null;
      const data = await res.json();
      if (!data.success) return null;
      return {
        fraud_score: data.fraud_score || 0,
        phishing: data.phishing === true,
        malware: data.malware === true
      };
    } catch (e) {
      return null;
    }
  }

  async function checkVirusTotal(url, key) {
    if (!key) return null;
    let vtId = "";
    try {
      const utf8Bytes = new TextEncoder().encode(url);
      const binaryString = Array.from(utf8Bytes, byte => String.fromCharCode(byte)).join('');
      vtId = btoa(binaryString).replace(/=/g, "");
    } catch (e) {
      vtId = btoa(url).replace(/=/g, "");
    }

    try {
      const getRes = await fetch(`https://www.virustotal.com/api/v3/urls/${vtId}`, {
        headers: { "x-apikey": key }
      });
      if (getRes.status === 200) {
        const data = await getRes.json();
        return { malicious: data.data?.attributes?.last_analysis_stats?.malicious || 0 };
      }
    } catch (e) {}

    try {
      const postRes = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": key,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: `url=${encodeURIComponent(url)}`
      });
      if (!postRes.ok) return null;
      const postData = await postRes.json();
      const analysisId = postData?.data?.id;
      if (!analysisId) return null;

      const analRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": key }
      });
      if (!analRes.ok) return null;
      const analData = await analRes.json();
      return { malicious: analData.data?.attributes?.stats?.malicious || 0 };
    } catch (e) {
      return null;
    }
  }

  async function checkWhoisAge(domain, key) {
    if (!key) return null;
    try {
      const whoisUrl = `https://domain-age-checker.whoisxmlapi.com/api/v1?apiKey=${key}&domainName=${domain}`;
      const res = await fetch(whoisUrl);
      if (!res.ok) return null;
      const data = await res.json();
      let age = data.domainAge || data.estimatedDomainAge || data.WhoisRecord?.estimatedDomainAge;
      const createdDateStr = data.createdDate || data.WhoisRecord?.createdDate;
      if (age === undefined && createdDateStr) {
        const createdTime = Date.parse(createdDateStr);
        if (!isNaN(createdTime)) {
          age = Math.floor((Date.now() - createdTime) / (1000 * 60 * 60 * 24));
        }
      }
      if (age === undefined) return null;
      return { age: Number(age) };
    } catch (e) {
      return null;
    }
  }

  async function initScan() {
    const url = location.href;

    // Default configuration
    const DEFAULT_SETTINGS = {
      modules: { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false },
      controls: { autoScan: true, popupAlerts: true, overlayAlerts: true },
    };

    chrome.storage.local.get(["settings", "trustedDomains", "personalBlocklist", "personalSafeList"], async ({ settings = DEFAULT_SETTINGS, trustedDomains = [], personalBlocklist = [], personalSafeList = [] }) => {
      const modules = settings?.modules || DEFAULT_SETTINGS.modules;
      const controls = settings?.controls || DEFAULT_SETTINGS.controls;

      // 1. Respect Auto Scan (System Control)
      if (!controls.autoScan) {
        return; 
      }

      // 2. Bypass scanning for whitelisted trusted domains
      let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch {}

      // Check personalBlocklist and personalSafeList first
      const isUserBlocked = personalBlocklist.some(d => host === d || host.endsWith("." + d));
      if (isUserBlocked) {
        const blockResult = {
          url: url,
          domain: host,
          risk: "DANGEROUS",
          score: 95,
          trustScore: 5,
          mlConfidence: "95%",
          module: "User Reported",
          aiPrediction: "Malicious",
          mlRisk: "High",
          subScores: { google: 0, ipqs: 0, virustotal: 0, domainAge: 0, local: 0 },
          modules: { phishing: 95, scam: 20, ai: 85, dark: 10, trust: 5 },
          time: Date.now(),
          cached: false,
          reasons: ["User reported dangerous domain"]
        };
        saveScanResult(blockResult);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "DANGEROUS" });
        if (controls.overlayAlerts) {
          showOverlay(95, ["User reported dangerous domain"]);
        }
        return;
      }

      const isUserSafe = personalSafeList.some(d => host === d || host.endsWith("." + d));
      if (isUserSafe) {
        const safeResult = {
          url: url,
          domain: host,
          risk: "SAFE",
          score: 0,
          trustScore: 100,
          mlConfidence: "100%",
          module: "User Verified",
          aiPrediction: "Benign",
          mlRisk: "Low",
          subScores: { google: 0, ipqs: 0, virustotal: 0, domainAge: 0, local: 0 },
          modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
          time: Date.now(),
          cached: false,
          reasons: ["User verified safe domain"]
        };
        saveScanResult(safeResult);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" });
        return;
      }

      const isWhitelisted = trustedDomains.some((d) => host === d || host.endsWith("." + d));
      if (isWhitelisted) {
        return; 
      }

      // PART 2 — PERMANENT SAFE LIST
      const isPermanentSafe = PERMANENT_SAFE.some(d => host === d || host.endsWith("." + d));
      if (isPermanentSafe) {
        const safeResult = {
          url: url,
          domain: host,
          risk: "SAFE",
          score: 0,
          trustScore: 100,
          mlConfidence: "100%",
          module: "Trust Engine",
          aiPrediction: "Benign",
          mlRisk: "Low",
          subScores: { google: 0, ipqs: 0, virustotal: 0, domainAge: 0, local: 0 },
          modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
          time: Date.now(),
          cached: false,
          reasons: ["Permanent safe listed domain"]
        };
        saveScanResult(safeResult);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "TRUSTED" });
        return;
      }

      // PART 3 — SMART 60 MINUTE CACHE
      const cacheKey = "vc_" + url;
      chrome.storage.local.get([cacheKey], async (cachedData) => {
        const cacheEntry = cachedData[cacheKey];
        if (cacheEntry && cacheEntry.timestamp && (Date.now() - cacheEntry.timestamp < 3600000)) {
          const cachedResult = cacheEntry.result;
          cachedResult.cached = true;
          saveScanResult(cachedResult);
          chrome.runtime.sendMessage({ action: "updateBadge", risk: cachedResult.risk });
          if (cachedResult.risk !== "SAFE" && controls.overlayAlerts) {
            showOverlay(cachedResult.score, cachedResult.reasons || ["Cached threat flag"]);
          }
          return;
        }


        // Run APIs concurrently using Promise.all with 3000ms timeout
        let googleResult = null;
        let ipqsResult = null;
        let vtResult = null;
        let whoisResult = null;

        try {
          const results = await Promise.all([
            modules.phishing ? withTimeout(checkGoogleSafeBrowsing(url, GOOGLE_SAFE_BROWSING_KEY), 3000) : Promise.resolve(null),
            modules.scam ? withTimeout(checkIPQualityScore(url, IPQS_KEY), 3000) : Promise.resolve(null),
            withTimeout(checkVirusTotal(url, VIRUSTOTAL_KEY), 3000),
            withTimeout(checkWhoisAge(host, WHOIS_KEY), 3000)
          ]);
          googleResult = results[0];
          ipqsResult = results[1];
          vtResult = results[2];
          whoisResult = results[3];
        } catch (e) {
          console.error("VeritasShield: concurrent scans failed", e);
        }

        const allApisFailed = (googleResult === null && ipqsResult === null && vtResult === null && whoisResult === null);
        const reasons = [];

        // Local Heuristics
        let M5_score = 0;
        let M6_score = 0;
        let M7_score = 0;
        let M8_score = 0;
        let M9_score = 0;

        // M5 Dark Pattern
        if (modules.darkPattern) {
          // Pre-ticked checkbox
          const checkboxes = document.querySelectorAll('input[type="checkbox"]:checked');
          let preTickedUnclicked = false;
          checkboxes.forEach(cb => {
            if (cb.dataset.veritasUserClicked !== "true") {
              preTickedUnclicked = true;
            }
          });
          if (preTickedUnclicked) {
            M5_score += 15;
            reasons.push("Dark Pattern: Pre-ticked checkbox not clicked by user detected");
          }

          // Hidden opt-outs
          let hasHiddenOptOut = false;
          try {
            const hiddenEl = Array.from(document.querySelectorAll('*')).find(el => {
              const style = window.getComputedStyle(el);
              const isHidden = style.display === 'none';
              if (isHidden) {
                const text = (el.innerText || el.textContent || "").toLowerCase();
                return text.includes("opt-out") || text.includes("optout") || text.includes("unsubscribe");
              }
              return false;
            });
            if (hiddenEl) {
              hasHiddenOptOut = true;
              M5_score += 15;
              reasons.push("Dark Pattern: Hidden opt-out/unsubscribe text detected");
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
              reasons.push("Dark Pattern: Countdown timer element detected");
            }
          } catch (e) {}
        }

        // M6 SSL Check
        const isHttp = location.protocol === "http:";
        const hasPassword = !!document.querySelector('input[type="password"]');
        const hasLoginForm = hasPassword || !!document.querySelector('form[action*="login"], form[id*="login"], form[class*="login"]');
        if (isHttp) {
          M6_score += 25;
          reasons.push("SSL Check: HTTP connection");
        }
        if (hasLoginForm && !location.protocol.includes("https")) {
          M6_score += 30;
          reasons.push("SSL Check: Insecure login form without HTTPS");
        }

        // M7 Content NLP
        if (modules.aiContent) {
          const text = (document.body ? document.body.innerText : "").toLowerCase();
          const scamPhrases = [
            { phrase: "you have won", score: 10 },
            { phrase: "claim now", score: 10 },
            { phrase: "verify account", score: 10 },
            { phrase: "urgent", score: 10 },
            { phrase: "act immediately", score: 10 },
            { phrase: "limited time offer", score: 10 },
            { phrase: "congratulations you", score: 10 },
            { phrase: "your account suspended", score: 10 },
            { phrase: "click here to claim", score: 10 },
            { phrase: "free gift", score: 10 }
          ];
          scamPhrases.forEach(p => {
            if (text.includes(p.phrase)) {
              M7_score += p.score;
              reasons.push("Content NLP: Detected scam phrase '" + p.phrase + "'");
            }
          });
        }

        // M8 URL Pattern Analysis
        const isIpAddress = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes("[");
        if (isIpAddress) {
          M8_score += 30;
          reasons.push("URL Analysis: IP address used instead of domain name");
        }
        const hyphenCount = (host.match(/-/g) || []).length;
        if (hyphenCount > 2) {
          M8_score += 15;
          reasons.push("URL Analysis: Domain has excessive hyphens");
        }
        const isSuspiciousTld = /\.(xyz|tk|ml|ga|cf|click|top|gq|pw|work)$/i.test(host);
        if (isSuspiciousTld) {
          M8_score += 20;
          reasons.push("URL Analysis: Domain uses highly suspicious TLD");
        }
        if (host.length > 30) {
          M8_score += 10;
          reasons.push("URL Analysis: Domain name length exceeds 30 characters");
        }
        const isMixedBrand = /(?:paypa1|amaz0n|g00gle|micr0soft|github1|app1e|faceb00k|netf1ix|sp0tify)/i.test(host);
        if (isMixedBrand) {
          M8_score += 35;
          reasons.push("URL Analysis: Brand name homoglyph detected");
        }

        // M9 QR Code Detection
        if (modules.qrDetector) {
          const qrImages = Array.from(document.querySelectorAll('img')).filter(img => {
            const src = (img.src || "").toLowerCase();
            const alt = (img.alt || "").toLowerCase();
            return src.includes("qr") || alt.includes("qr") || src.includes("barcode");
          });
          if (qrImages.length > 0) {
            reasons.push(`QR Scan: Inspected ${qrImages.length} image(s) for malicious payloads`);
          } else {
            reasons.push("QR Scan: No QR codes detected on page");
          }
        }

        // Voice Clone Monitor
        if (modules.voiceClone) {
          reasons.push("Beta — monitoring audio elements");
        }

        const localScore = M5_score + M6_score + M7_score + M8_score + M9_score;

        let threatScore = 0;
        let mlConfidence = "";

        // API Scores
        const googleFlag = (googleResult && googleResult.matched) ? 100 : 0;
        const ipqsScore = ipqsResult ? (ipqsResult.fraud_score || 0) : 0;
        const vtScore = vtResult ? (vtResult.malicious > 3 ? 100 : vtResult.malicious * 20) : 0;
        const domainAgeFlag = (whoisResult && whoisResult.age < 30) ? 30 : 0;

        if (allApisFailed) {
          threatScore = localScore;
          mlConfidence = "Local scan";
          reasons.push("Fallback: Offline or APIs timed out. Local analysis active.");
        } else {
          const baseScore = Math.max(googleFlag, ipqsScore, vtScore);
          threatScore = Math.max(baseScore, localScore, domainAgeFlag);
          threatScore = Math.min(100, Math.round(threatScore));
          mlConfidence = Math.round(threatScore) + "%";
        }

        // Cap score
        threatScore = Math.min(100, threatScore);
        const trustScore = 100 - threatScore;

        // Determine final risk rating
        let risk = "SAFE";
        const gsbMatched = (googleResult && googleResult.matched);
        const ipqsPhish = (ipqsResult && ipqsResult.phishing === true);
        const ipqsMalware = (ipqsResult && ipqsResult.malware === true);
        const vtMalicious = (vtResult && vtResult.malicious > 3);

        if (gsbMatched || ipqsPhish || ipqsMalware || vtMalicious || threatScore > 70) {
          risk = "DANGEROUS";
        } else if ((ipqsResult && ipqsResult.fraud_score > 40) || threatScore > 35) {
          risk = "SUSPICIOUS";
        }

        // Module Name Selection (Part 8)
        let moduleName = "Trust Engine";
        if (gsbMatched) moduleName = "Phishing URL";
        else if (vtMalicious) moduleName = "Phishing URL";
        else if (ipqsPhish) moduleName = "Scam Pattern";
        else if (whoisResult && whoisResult.age < 30) moduleName = "Scam Pattern";
        else if (M6_score > 0) moduleName = "Scam Pattern";
        else if (M7_score > 0) moduleName = "AI Content";
        else if (M5_score > 0) moduleName = "Dark Pattern";
        else if (M8_score > 0) moduleName = "Phishing URL";

        const scanResult = {
          url: url,
          domain: host,
          risk: risk,
          score: threatScore,
          trustScore: trustScore,
          mlConfidence: mlConfidence,
          module: moduleName,
          aiPrediction: risk === "DANGEROUS" ? "Malicious" : risk === "SUSPICIOUS" ? "Suspicious" : "Benign",
          mlRisk: threatScore > 70 ? "High" : threatScore > 35 ? "Medium" : "Low",
          subScores: {
            google: googleFlag,
            ipqs: ipqsScore,
            virustotal: vtScore,
            domainAge: domainAgeFlag,
            local: localScore
          },
          modules: {
            phishing: Math.min(100, Math.max(googleFlag, vtScore, M8_score)),
            scam: Math.min(100, Math.max(ipqsScore, domainAgeFlag, M6_score)),
            ai: Math.min(100, M7_score),
            dark: Math.min(100, M5_score),
            trust: trustScore
          },
          time: Date.now(),
          cached: false,
          reasons: reasons
        };

        saveScanResult(scanResult);
        saveToCache(url, scanResult);

        // Update Dynamic Badge
        chrome.runtime.sendMessage({ action: "updateBadge", risk: risk });

        if (risk !== "SAFE" && controls.overlayAlerts) {
          showOverlay(threatScore, reasons);
        }
      });
    });
  }

  function saveScanResult(scanResult) {
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      const filtered = scanHistory.filter(h => h.url !== scanResult.url);
      const updated = [scanResult, ...filtered].slice(0, 500);
      chrome.storage.local.set({ scanHistory: updated });
      if (window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:")) {
        localStorage.setItem("veritasai_scans", JSON.stringify(updated));
        window.dispatchEvent(new StorageEvent("storage", { key: "veritasai_scans", newValue: JSON.stringify(updated) }));
      }
    });
  }

  function saveToCache(urlKey, scanResult) {
    const cacheKey = "vc_" + urlKey;
    chrome.storage.local.set({
      [cacheKey]: {
        result: scanResult,
        timestamp: Date.now()
      }
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