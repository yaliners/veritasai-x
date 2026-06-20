// PART 1 — API KEYS at very top:
const GOOGLE_KEY = "AIzaSyAhlLFE9g0jR7wVbq-pRTMyAYRRLhfwrWs";
const IPQS_KEY = "sYnwTP8nMlIBGLK8dCXbUyDQEwQSXCiO";
const VT_KEY = "f50bfa739b08364404699b51bc26f326b2923a20222007b179e8b2b048a486e8";
const WHOIS_KEY = "at_XlkBiABAXaNSHT8KMsLEGgnssnVc2";

// PART 2 — PERMANENT SAFE (skip APIs for these only):
const PERMANENT_SAFE = [
  "google.com", "youtube.com", "github.com",
  "microsoft.com", "apple.com", "amazon.com",
  "claude.ai", "chatgpt.com", "linkedin.com",
  "twitter.com", "instagram.com", "facebook.com",
  "whatsapp.com", "wikipedia.org", "stackoverflow.com",
  "netflix.com", "spotify.com", "reddit.com",
  "anthropic.com", "openai.com",
  "veritasai-shield.vercel.app"
];

const getBaseDomain = (hostname) => {
  return hostname.replace(/^www\./, "");
};

// PART 4 — TIMEOUT HELPER:
const withTimeout = (promise, ms) => {
  return Promise.race([
    promise,
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error("timeout")), ms)
    )
  ]);
};

// PART 5 — GOOGLE SAFE BROWSING API:
const checkGoogle = async (url, googleKey) => {
  try {
    const res = await withTimeout(fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${googleKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "veritasai", clientVersion: "2.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING", 
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    ), 3000);
    
    if (!res.ok) return { score: 0, matched: false, reason: null };
    
    const data = await res.json();
    const matched = data.matches && data.matches.length > 0;
    const threatType = matched ? data.matches[0].threatType : null;
    
    return {
      score: matched ? 100 : 0,
      matched,
      reason: matched ? `Google flagged: ${threatType}` : null
    };
  } catch (e) {
    console.warn("Google API failed:", e.message);
    return { score: 0, matched: false, reason: null, error: true };
  }
};

// PART 6 — IPQUALITYSCORE API:
const checkIPQS = async (url, ipqsKey) => {
  try {
    const encoded = encodeURIComponent(url);
    const res = await withTimeout(fetch(
      `https://ipqualityscore.com/api/json/url/${ipqsKey}/${encoded}?strictness=1&allow_public_access_points=true`
    ), 3000);
    
    if (!res.ok) return { score: 0, reason: null };
    
    const data = await res.json();
    
    if (!data.success) return { score: 0, reason: null, error: true };
    
    const score = data.fraud_score || 0;
    const reasons = [];
    
    if (data.phishing) reasons.push("Phishing detected by IPQS");
    if (data.malware) reasons.push("Malware detected by IPQS");
    if (data.suspicious) reasons.push("Suspicious patterns detected");
    if (data.spam) reasons.push("Spam domain detected");
    if (score > 75) reasons.push(`High fraud score: ${score}`);
    
    return {
      score,
      phishing: data.phishing || false,
      malware: data.malware || false,
      suspicious: data.suspicious || false,
      reason: reasons.length > 0 ? reasons.join(", ") : null,
      forceDANGEROUS: data.phishing || data.malware,
      forceSUSPICIOUS: score > 40
    };
  } catch (e) {
    console.warn("IPQS API failed:", e.message);
    return { score: 0, reason: null, error: true };
  }
};

// PART 7 — VIRUSTOTAL API:
const checkVirusTotal = async (url, vtKey) => {
  try {
    const urlId = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    
    const res = await withTimeout(fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { "x-apikey": vtKey } }
    ), 3000);
    
    if (res.status === 404) {
      const submitRes = await withTimeout(fetch(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: {
            "x-apikey": vtKey,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: `url=${encodeURIComponent(url)}`
        }
      ), 3000);
      
      if (!submitRes.ok) return { score: 0, malicious: 0, reason: null };
      
      const submitData = await submitRes.json();
      const analysisId = submitData.data?.id;
      
      if (!analysisId) return { score: 0, malicious: 0, reason: null };
      
      const pollRes = await withTimeout(fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { "x-apikey": vtKey } }
      ), 3000);
      
      if (!pollRes.ok) return { score: 0, malicious: 0, reason: null };
      
      const pollData = await pollRes.json();
      const stats = pollData.data?.attributes?.stats || {};
      const malicious = stats.malicious || 0;
      const total = (stats.malicious || 0) + (stats.harmless || 0) + 
                    (stats.suspicious || 0) + (stats.undetected || 0);
      
      return {
        score: malicious > 3 ? 100 : malicious > 0 ? malicious * 20 : 0,
        malicious,
        total,
        reason: malicious > 0 ? 
          `${malicious}/${total} antivirus engines flagged this URL` : null,
        forceDANGEROUS: malicious > 3
      };
    }
    
    if (!res.ok) return { score: 0, malicious: 0, reason: null, error: true };
    
    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const total = (stats.malicious || 0) + (stats.harmless || 0) + 
                  (stats.suspicious || 0) + (stats.undetected || 0);
    
    return {
      score: malicious > 3 ? 100 : malicious > 0 ? malicious * 20 : 0,
      malicious,
      total,
      reason: malicious > 0 ?
        `${malicious}/${total} antivirus engines flagged this URL` : null,
      forceDANGEROUS: malicious > 3
    };
  } catch (e) {
    console.warn("VirusTotal API failed:", e.message);
    return { score: 0, malicious: 0, reason: null, error: true };
  }
};

// PART 8 — WHOIS DOMAIN AGE API:
const checkWhois = async (domain, whoisKey) => {
  try {
    const res = await withTimeout(fetch(
      `https://domain-age-checker.whoisxmlapi.com/api/v1?apiKey=${whoisKey}&domainName=${domain}`
    ), 3000);
    
    if (!res.ok) return { ageDays: null, flag: 0, reason: null };
    
    const data = await res.json();
    let ageDays = null;
    
    if (data.domainAge?.days) {
      ageDays = parseInt(data.domainAge.days);
    } else if (data.estimatedDomainAge) {
      ageDays = parseInt(data.estimatedDomainAge);
    }
    
    if (ageDays === null) return { ageDays: null, flag: 0, reason: null };
    
    const flag = ageDays < 30 ? 30 : ageDays < 90 ? 15 : 0;
    const reason = ageDays < 30 ? 
      `Domain registered only ${ageDays} days ago — high risk` :
      ageDays < 90 ?
      `Domain registered ${ageDays} days ago — relatively new` : null;
    
    return { ageDays, flag, reason };
  } catch (e) {
    console.warn("Whois API failed:", e.message);
    return { ageDays: null, flag: 0, reason: null, error: true };
  }
};

// PART 9 — LOCAL EDGE AI MODULES:
const runLocalModules = () => {
  let localScore = 0;
  const reasons = [];
  
  // M6 SSL Check
  if (window.location.protocol === "http:") {
    localScore += 25;
    reasons.push("No HTTPS encryption detected");
  }
  
  // M7 Content NLP
  const bodyText = document.body?.innerText?.toLowerCase() || "";
  const scamPhrases = [
    "you have won", "claim now", "verify account",
    "act immediately", "limited time offer",
    "congratulations you", "your account suspended",
    "click here to claim", "free gift", "urgent action required",
    "wire transfer", "bitcoin payment", "gift card required",
    "irs notice", "legal action", "arrest warrant"
  ];
  
  scamPhrases.forEach(phrase => {
    if (bodyText.includes(phrase)) {
      localScore += 10;
      reasons.push(`Scam phrase detected: "${phrase}"`);
    }
  });
  
  // M8 URL Pattern Analysis
  const host = window.location.hostname;
  
  // IP address instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    localScore += 30;
    reasons.push("IP address used instead of domain name");
  }
  
  // Excessive hyphens
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    localScore += 15;
    reasons.push(`Suspicious domain with ${hyphenCount} hyphens`);
  }
  
  // Suspicious TLDs
  const suspiciousTLDs = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".click",
    ".top", ".gq", ".pw", ".work", ".loan", ".date",
    ".racing", ".win", ".download", ".stream"
  ];
  suspiciousTLDs.forEach(tld => {
    if (host.endsWith(tld)) {
      localScore += 20;
      reasons.push(`Suspicious domain extension: ${tld}`);
    }
  });
  
  // Very long domain
  if (host.length > 30) {
    localScore += 10;
    reasons.push(`Unusually long domain name (${host.length} characters)`);
  }
  
  // Brand homoglyphs
  const homoglyphs = [
    "paypa1", "amaz0n", "g00gle", "microsoFt",
    "app1e", "faceb00k", "netfl1x", "lnstagram"
  ];
  homoglyphs.forEach(h => {
    if (host.includes(h)) {
      localScore += 35;
      reasons.push(`Brand impersonation detected: ${h}`);
    }
  });
  
  // M5 Dark Pattern
  try {
    const checkedBoxes = document.querySelectorAll(
      'input[type="checkbox"]:checked'
    );
    if (checkedBoxes.length > 0) {
      localScore += 10;
      reasons.push("Pre-checked consent boxes detected");
    }
    
    const hiddenText = Array.from(
      document.querySelectorAll("*")
    ).filter(el => {
      const style = window.getComputedStyle(el);
      return style.display === "none" && 
             el.innerText && (
               el.innerText.toLowerCase().includes("opt-out") ||
               el.innerText.toLowerCase().includes("unsubscribe")
             );
    });
    
    if (hiddenText.length > 0) {
      localScore += 15;
      reasons.push("Hidden opt-out text detected");
    }
  } catch (e) {}
  
  return { localScore: Math.min(localScore, 40), reasons };
};

// DETECTION EVIDENCE PANEL OVERLAY RENDERER:
const showOverlay = (score, reasons) => {
  if (document.getElementById("veritas-overlay")) return;
  const el = document.createElement("div");
  el.id = "veritas-overlay";

  const evidenceListHtml = reasons.map(function(r) {
    const cleanText = r.replace(/^[✓\s*-]+/, "");
    return '<li style="margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;color:#e6edf7;">' +
           '<span style="color:#22c55e;font-weight:bold;">✓</span>' +
           '<span style="text-align:left;">' + cleanText + '</span>' +
           '</li>';
  }).join("");

  const isLocalOnly = reasons.some(function(r){return r.indexOf("Local scan only") !== -1;});

  const panelHtml = 
    '<div style="background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.25);border-radius:10px;padding:14px;margin-bottom:20px;text-align:left;">' +
      '<div style="display:flex;justify-content:between;align-items:center;border-bottom:1px solid rgba(239,68,68,0.15);padding-bottom:8px;margin-bottom:8px;justify-content:space-between;">' +
        '<span style="font-size:12px;font-weight:700;color:#ef4444;text-transform:uppercase;letter-spacing:0.05em;">Evidence</span>' +
        '<div style="display:flex;gap:4px;align-items:center;">' +
          (isLocalOnly ? '<span style="font-size:10px;font-weight:700;color:#f59e0b;background:rgba(245,158,11,0.12);padding:2px 8px;border-radius:4px;border:1px solid rgba(245,158,11,0.3);margin-right:6px;">Local scan only</span>' : '') +
          '<span style="font-size:12px;font-weight:700;color:#ef4444;background:rgba(239,68,68,0.12);padding:2px 8px;border-radius:4px;">Threat Score: ' + score + '</span>' +
        '</div>' +
      '</div>' +
      '<ul style="list-style:none;padding:0;margin:0;font-size:12px;line-height:1.5;text-align:left;">' +
        evidenceListHtml +
      '</ul>' +
    '</div>';

  el.innerHTML = '<div style="position:fixed;inset:0;background:rgba(2,8,23,0.85);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;">' +
    '<div style="max-width:480px;width:100%;background:#081225;border:1px solid rgba(239,68,68,0.5);border-radius:16px;padding:24px;color:#e6edf7;box-shadow:0 20px 60px rgba(0,0,0,0.6);text-align:center;">' +
      '<p style="font-size:11px;letter-spacing:0.2em;color:#ef4444;font-weight:700;margin-bottom:4px;">VERITAS SHIELD ALERT</p>' +
      '<h2 style="font-size:22px;margin:0 0 12px 0;">&#9888; Threat Detected</h2>' +
      panelHtml +
      '<div style="display:flex;gap:8px;">' +
        '<button id="vleave" style="flex:1;padding:10px;border:none;border-radius:10px;background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;font-weight:700;cursor:pointer;">Leave Site</button>' +
        '<button id="vcont" style="flex:1;padding:10px;border:1px solid rgba(154,168,194,0.4);border-radius:10px;background:transparent;color:#9aa8c2;font-weight:600;cursor:pointer;">Continue Anyway</button>' +
      '</div>' +
    '</div>' +
  '</div>';

  document.documentElement.appendChild(el);
  el.querySelector("#vleave").onclick = function() { history.back(); };
  el.querySelector("#vcont").onclick = function() { el.remove(); };
};

// PART 11 — SAVE AND BROADCAST:
const saveAndBroadcast = async (result) => {
  chrome.runtime.sendMessage({
    action: "updateBadge",
    risk: result.risk
  });
  
  const { scanHistory = [] } = await chrome.storage.local.get(["scanHistory"]);
  const filtered = scanHistory.filter(s => s.domain !== result.domain);
  const updated = [result, ...filtered].slice(0, 500);
  
  await chrome.storage.local.set({ scanHistory: updated });
  
  const isVeritasSite = window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:");
  if (isVeritasSite) {
    localStorage.setItem("veritasai_scans", JSON.stringify(updated));
    window.dispatchEvent(new StorageEvent("storage", {
      key: "veritasai_scans",
      newValue: JSON.stringify(updated)
    }));
  }
};

// PART 10 — MAIN SCAN FUNCTION:
const initScan = async () => {
  const fullUrl = window.location.href;
  const hostname = window.location.hostname.toLowerCase();
  const baseDomain = getBaseDomain(hostname);
  
  const { settings } = await chrome.storage.local.get(["settings"]);
  const controls = settings?.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
  if (!controls.autoScan) return;
  
  const isPermanentSafe = PERMANENT_SAFE.some(
    safe => baseDomain === safe || baseDomain.endsWith("." + safe)
  );
  
  if (isPermanentSafe) {
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
      subScores: { google: 0, ipqs: 0, virustotal: 0, domainAge: 0, local: 0 },
      time: new Date().toISOString(),
      cached: false
    };
    await saveAndBroadcast(result);
    return;
  }
  
  chrome.runtime.sendMessage({ action: "updateBadge", risk: "SCANNING" });
  
  const cacheKey = "vc_" + baseDomain;
  const cached = await chrome.storage.local.get([cacheKey]);
  
  if (cached[cacheKey]) {
    const entry = cached[cacheKey];
    const age = Date.now() - entry.timestamp;
    if (age < 60 * 60 * 1000) {
      const result = { ...entry.result, cached: true };
      await saveAndBroadcast(result);
      return;
    }
  }
  
  const apiKeys = settings?.apiKeys || {};
  const googleKey = apiKeys.googleSafeBrowsing || GOOGLE_KEY;
  const ipqsKey = apiKeys.ipQualityScore || IPQS_KEY;
  const vtKey = apiKeys.virusTotal || VT_KEY;
  const whoisKey = apiKeys.whoisXml || WHOIS_KEY;

  const [google, ipqs, vt, whois] = await Promise.all([
    checkGoogle(fullUrl, googleKey),
    checkIPQS(fullUrl, ipqsKey),
    checkVirusTotal(fullUrl, vtKey),
    checkWhois(baseDomain, whoisKey)
  ]);
  
  const { localScore, reasons: localReasons } = runLocalModules();
  
  const googleFlag = google.matched ? 100 : 0;
  const ipqsScore = ipqs.score || 0;
  const vtScore = vt.score || 0;
  const domainAgeFlag = whois.flag || 0;
  
  let threatScore = (
    googleFlag * 0.25 +
    ipqsScore * 0.40 +
    vtScore * 0.35
  ) + localScore + domainAgeFlag;
  
  threatScore = Math.min(Math.round(threatScore), 100);
  const trustScore = Math.max(0, 100 - threatScore);
  
  let risk = "SAFE";
  
  if (
    google.matched ||
    ipqs.forceDANGEROUS ||
    vt.forceDANGEROUS ||
    threatScore > 70
  ) {
    risk = "DANGEROUS";
  } else if (
    ipqs.forceSUSPICIOUS ||
    threatScore > 35
  ) {
    risk = "SUSPICIOUS";
  }
  
  const allReasons = [];
  if (google.reason) allReasons.push(google.reason);
  if (ipqs.reason) allReasons.push(ipqs.reason);
  if (vt.reason) allReasons.push(vt.reason);
  if (whois.reason) allReasons.push(whois.reason);
  allReasons.push(...localReasons);
  
  const apisWorked = !google.error || !ipqs.error || !vt.error || !whois.error;
  if (!apisWorked) allReasons.push("Local scan only — APIs unavailable");
  
  let module = "Trust Engine";
  if (google.matched) module = "Phishing URL";
  else if (vt.forceDANGEROUS) module = "Malware Detection";
  else if (ipqs.forceDANGEROUS) module = "Scam Pattern";
  else if (whois.flag > 0) module = "New Domain";
  else if (localScore > 20) module = "Content NLP";
  
  const mlRisk = threatScore > 70 ? "High" : 
                 threatScore > 35 ? "Medium" : "Low";
  
  const result = {
    url: fullUrl,
    domain: baseDomain,
    risk,
    score: threatScore,
    trustScore,
    mlConfidence: threatScore + "%",
    module,
    aiPrediction: risk === "DANGEROUS" ? "Threat detected — do not proceed" :
                  risk === "SUSPICIOUS" ? "Suspicious activity detected" :
                  "No threats detected",
    mlRisk,
    reasons: allReasons.length > 0 ? allReasons : ["No threat signals detected"],
    subScores: {
      google: googleFlag,
      ipqs: ipqsScore,
      virustotal: vtScore,
      domainAge: domainAgeFlag,
      local: localScore
    },
    time: new Date().toISOString(),
    cached: false
  };
  
  await chrome.storage.local.set({
    [cacheKey]: { result, timestamp: Date.now() }
  });
  
  await saveAndBroadcast(result);

  if (result.risk !== "SAFE" && controls.overlayAlerts) {
    showOverlay(result.score, result.reasons);
  }
};

// PART 12 — INITIALIZE:
const isVeritasSite = window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:");

if (isVeritasSite) {
  document.documentElement.dataset.veritasShieldInstalled = "true";

  window.addEventListener("veritas_ping", () => {
    window.dispatchEvent(new CustomEvent("veritas_pong"));
  });
  window.dispatchEvent(new CustomEvent("veritas_pong"));

  chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
    localStorage.setItem("veritasai_scans", JSON.stringify(scanHistory));
    window.dispatchEvent(new StorageEvent("storage", { key: "veritasai_scans", newValue: JSON.stringify(scanHistory) }));
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.scanHistory) {
      const updated = changes.scanHistory.newValue || [];
      localStorage.setItem("veritasai_scans", JSON.stringify(updated));
      window.dispatchEvent(new StorageEvent("storage", {
        key: "veritasai_scans",
        newValue: JSON.stringify(updated)
      }));
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
          const domains = parsed.map(x => x.domain.toLowerCase());
          chrome.storage.local.set({ trustedDomains: domains });
        }
      } catch (err) {}
    }
  });
} else {
  if (
    document.readyState === "complete" ||
    document.readyState === "interactive"
  ) {
    initScan();
  } else {
    window.addEventListener("DOMContentLoaded", initScan);
  }
}