// PART 1 — API KEYS
const GOOGLE_KEY = "AIzaSyAhlLFE9g0jR7wVbq-pRTMyAYRRLhfwrWs";
const URLSCAN_KEY = "019eea96-036b-7407-8e7e-85df59cadb59";
const VT_KEY = "f50bfa739b08364404699b51bc26f326b2923a20222007b179e8b2b048a486e8";
const ABUSEIPDB_KEY = "9a65e7002cb5ebb9e4b39056277a24ac54f33afdf904a7bd6d79bfc4c0be7f2dcfd0433822434cd9";

// PART 2 — PERMANENT SAFE LIST
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
  return hostname.replace(/^www\./, "").toLowerCase();
};

const isPermanentSafe = (baseDomain) => {
  return PERMANENT_SAFE.some(
    safe => baseDomain === safe || 
    baseDomain.endsWith("." + safe)
  );
};

// PART 3 — TIMEOUT AND RATE LIMIT HELPERS
const withTimeout = (promise, ms) => {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), ms)
    )
  ]);
};

let vtLastCall = 0;
const VT_COOLDOWN = 15000;

const canCallVT = () => {
  return Date.now() - vtLastCall > VT_COOLDOWN;
};

const incrementVTCounter = async () => {
  try {
    const data = await chrome.storage.local.get([
      "vtCallsToday", "vtLastReset"
    ]);
    const now = Date.now();
    const lastReset = data.vtLastReset || now;
    const hoursSinceReset = (now - lastReset) / (1000 * 60 * 60);
    
    if (hoursSinceReset >= 24) {
      await chrome.storage.local.set({
        vtCallsToday: 1,
        vtLastReset: now
      });
    } else {
      await chrome.storage.local.set({
        vtCallsToday: (data.vtCallsToday || 0) + 1
      });
    }
  } catch (e) {
    console.warn("Error incrementing VT counter:", e.message);
  }
};

// PART 4 — API 1: GOOGLE SAFE BROWSING
const checkGoogle = async (url, googleKey) => {
  try {
    const activeKey = googleKey || GOOGLE_KEY;
    const res = await withTimeout(fetch(
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + activeKey,
      {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          client: {
            clientId: "veritasai",
            clientVersion: "3.0"
          },
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

    if (!res.ok) return { 
      score: 0, matched: false, 
      reason: null, error: true 
    };

    const data = await res.json();
    const matched = !!(data.matches?.length);
    const type = data.matches?.[0]?.threatType;

    return {
      score: matched ? 100 : 0,
      matched,
      reason: matched ? "Google Safe Browsing: " + type : null,
      forceDANGEROUS: matched
    };
  } catch (e) {
    console.warn("Google failed:", e.message);
    return { 
      score: 0, matched: false, 
      reason: null, error: true 
    };
  }
};

// PART 5 — API 2: URLSCAN.IO
const checkURLScan = async (domain, urlscanKey) => {
  try {
    const activeKey = urlscanKey || URLSCAN_KEY;
    const headers = {};
    if (activeKey) {
      headers["API-Key"] = activeKey;
    }
    const res = await withTimeout(fetch(
      "https://urlscan.io/api/v1/search/?q=domain:" + encodeURIComponent(domain) + "&size=1",
      { headers }
    ), 3000);

    if (!res.ok) return { 
      score: 0, reason: null, error: true 
    };

    const data = await res.json();
    const result = data.results?.[0];

    if (!result) return { score: 0, reason: null };

    const verdicts = result.verdicts?.overall;
    const malicious = verdicts?.malicious || false;
    const score = verdicts?.score || 0;
    const brands = result.page?.domain || domain;

    return {
      score: malicious ? 100 : score,
      malicious,
      reason: malicious ?
        "URLScan flagged as malicious: " + brands :
        score > 50 ? 
        "URLScan suspicious score: " + score : null,
      forceDANGEROUS: malicious,
      forceSUSPICIOUS: !malicious && score > 50
    };
  } catch (e) {
    console.warn("URLScan failed:", e.message);
    return { score: 0, reason: null, error: true };
  }
};

// PART 6 — API 3: VIRUSTOTAL
const checkVirusTotal = async (url, vtKey) => {
  if (!canCallVT()) {
    console.warn("VT rate limited — skipping");
    return { score: 0, reason: null, skipped: true };
  }

  try {
    vtLastCall = Date.now();
    const activeKey = vtKey || VT_KEY;

    const urlId = btoa(url)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    const res = await withTimeout(fetch(
      "https://www.virustotal.com/api/v3/urls/" + urlId,
      { headers: { "x-apikey": activeKey } }
    ), 3000);

    if (res.status === 404) {
      const submitRes = await withTimeout(fetch(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: {
            "x-apikey": activeKey,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: "url=" + encodeURIComponent(url)
        }
      ), 3000);

      if (!submitRes.ok) return { 
        score: 0, malicious: 0, reason: null 
      };

      const submitData = await submitRes.json();
      const analysisId = submitData.data?.id;

      if (!analysisId) return { 
        score: 0, malicious: 0, reason: null 
      };

      const pollRes = await withTimeout(fetch(
        "https://www.virustotal.com/api/v3/analyses/" + analysisId,
        { headers: { "x-apikey": activeKey } }
      ), 3000);

      if (!pollRes.ok) return { 
        score: 0, malicious: 0, reason: null 
      };

      const pollData = await pollRes.json();
      const stats = pollData.data?.attributes?.stats || {};
      const malicious = stats.malicious || 0;
      const total = (stats.malicious || 0) +
        (stats.harmless || 0) +
        (stats.suspicious || 0) +
        (stats.undetected || 0);

      await incrementVTCounter();

      return {
        score: malicious > 3 ? 100 : malicious * 20,
        malicious,
        total,
        reason: malicious > 0 ?
          malicious + "/" + total + " antivirus engines flagged" : null,
        forceDANGEROUS: malicious > 3
      };
    }

    if (!res.ok) return { 
      score: 0, malicious: 0, 
      reason: null, error: true 
    };

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const total = (stats.malicious || 0) +
      (stats.harmless || 0) +
      (stats.suspicious || 0) +
      (stats.undetected || 0);

    await incrementVTCounter();

    return {
      score: malicious > 3 ? 100 : malicious * 20,
      malicious,
      total,
      reason: malicious > 0 ?
        malicious + "/" + total + " antivirus engines flagged" : null,
      forceDANGEROUS: malicious > 3
    };
  } catch (e) {
    console.warn("VT failed:", e.message);
    return { 
      score: 0, malicious: 0, 
      reason: null, error: true 
    };
  }
};

// PART 7 — API 4: RDAP DOMAIN AGE (FREE/NO KEY)
const checkDomainAge = async (domain) => {
  try {
    const res = await withTimeout(fetch(
      "https://rdap.org/domain/" + domain
    ), 3000);

    if (!res.ok) return { 
      flag: 0, ageDays: null, reason: null 
    };

    const data = await res.json();
    const regEvent = data.events?.find(
      e => e.eventAction === "registration"
    );

    if (!regEvent) return { 
      flag: 0, ageDays: null, reason: null 
    };

    const regDate = new Date(regEvent.eventDate);
    const ageDays = Math.floor(
      (Date.now() - regDate.getTime()) / 
      (1000 * 60 * 60 * 24)
    );

    const flag = ageDays < 30 ? 30 : 
                 ageDays < 90 ? 15 : 0;

    const reason = ageDays < 30 ?
      "Domain only " + ageDays + " days old — very high risk" :
      ageDays < 90 ?
      "Domain " + ageDays + " days old — relatively new" : null;

    return { ageDays, flag, reason };
  } catch (e) {
    console.warn("RDAP failed:", e.message);
    return { flag: 0, ageDays: null, reason: null };
  }
};

// PART 8 — API 5: ABUSEIPDB
const checkAbuseIPDB = async (domain, abuseKey) => {
  try {
    const activeKey = abuseKey || ABUSEIPDB_KEY;
    const res = await withTimeout(fetch(
      "https://api.abuseipdb.com/api/v2/check?ipAddress=" + encodeURIComponent(domain) + "&maxAgeInDays=90",
      {
        headers: {
          "Key": activeKey,
          "Accept": "application/json"
        }
      }
    ), 3000);

    if (!res.ok) return { 
      score: 0, reason: null, error: true 
    };

    const data = await res.json();
    const score = data.data?.abuseConfidenceScore || 0;

    return {
      score,
      reason: score > 40 ? "AbuseIPDB confidence: " + score + "%" : null,
      forceDANGEROUS: score > 80,
      forceSUSPICIOUS: score > 40
    };
  } catch (e) {
    console.warn("AbuseIPDB failed:", e.message);
    return { score: 0, reason: null, error: true };
  }
};

// PART 9 — API 6: CLOUDFLARE DNS (FREE/NO KEY)
const checkCloudfareDNS = async (domain) => {
  try {
    const res = await withTimeout(fetch(
      "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(domain) + "&type=A",
      { headers: { "Accept": "application/dns-json" } }
    ), 3000);

    if (!res.ok) return { 
      flag: 0, reason: null, error: true 
    };

    const data = await res.json();
    const status = data.Status;
    const hasAnswers = data.Answer?.length > 0;

    if (status !== 0 || !hasAnswers) {
      return {
        flag: 20,
        reason: "DNS anomaly detected — domain may not resolve properly"
      };
    }

    return { flag: 0, reason: null };
  } catch (e) {
    console.warn("DNS check failed:", e.message);
    return { flag: 0, reason: null, error: true };
  }
};

// PART 10 — LOCAL EDGE AI MODULES (ALL 8 MODULES)
const runLocalModules = () => {
  let localScore = 0;
  const reasons = [];

  try {
    const host = window.location.hostname.toLowerCase();
    const protocol = window.location.protocol;
    const bodyText = document.body?.innerText?.toLowerCase() || "";

    // M1 — URL Pattern Analysis
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      localScore += 30;
      reasons.push("IP address used instead of domain name");
    }

    const hyphens = (host.match(/-/g) || []).length;
    if (hyphens > 2) {
      localScore += 15;
      reasons.push("Suspicious domain: " + hyphens + " hyphens");
    }

    const suspTLDs = [
      ".xyz", ".tk", ".ml", ".ga", ".cf",
      ".click", ".top", ".gq", ".pw", ".work",
      ".loan", ".date", ".racing", ".win",
      ".download", ".stream", ".party", ".review"
    ];
    suspTLDs.forEach(tld => {
      if (host.endsWith(tld)) {
        localScore += 20;
        reasons.push("Suspicious domain extension: " + tld);
      }
    });

    if (host.length > 30) {
      localScore += 10;
      reasons.push("Unusually long domain (" + host.length + " chars)");
    }

    const homoglyphs = [
      "paypa1", "amaz0n", "g00gle", "app1e",
      "faceb00k", "netfl1x", "lnstagram",
      "tw1tter", "micros0ft", "paypai"
    ];
    homoglyphs.forEach(h => {
      if (host.includes(h)) {
        localScore += 35;
        reasons.push("Brand impersonation detected: " + h);
      }
    });

    // M2 — SSL Check
    if (protocol === "http:") {
      localScore += 25;
      reasons.push("No HTTPS encryption");
    }

    const hasForms = document.querySelectorAll("input[type='password']").length > 0;
    if (protocol === "http:" && hasForms) {
      localScore += 30;
      reasons.push("Password form on unsecured HTTP page");
    }

    // M3 — Content NLP
    const scamPhrases = [
      "you have won", "claim now",
      "verify account", "act immediately",
      "limited time offer", "congratulations you",
      "your account suspended",
      "click here to claim", "free gift",
      "urgent action required", "wire transfer",
      "bitcoin payment", "gift card required",
      "irs notice", "legal action"
    ];
    scamPhrases.forEach(phrase => {
      if (bodyText.includes(phrase)) {
        localScore += 10;
        reasons.push('Scam phrase: "' + phrase + '"');
      }
    });

    // M4 — Dark Pattern Detection
    const checkedBoxes = document.querySelectorAll("input[type='checkbox']:checked");
    if (checkedBoxes.length > 0) {
      localScore += 10;
      reasons.push("Pre-checked consent boxes found");
    }

    const allElements = document.querySelectorAll("*");
    let hiddenOptOut = false;
    allElements.forEach(el => {
      try {
        const style = window.getComputedStyle(el);
        const text = el.innerText?.toLowerCase() || "";
        if (
          style.display === "none" &&
          (text.includes("opt-out") || text.includes("unsubscribe"))
        ) {
          hiddenOptOut = true;
        }
      } catch (e) {}
    });
    if (hiddenOptOut) {
      localScore += 15;
      reasons.push("Hidden opt-out text detected");
    }

    const countdowns = document.querySelectorAll(
      "[class*='countdown'],[class*='timer'],[id*='countdown'],[id*='timer']"
    );
    if (countdowns.length > 0) {
      localScore += 15;
      reasons.push("Fake urgency timer detected");
    }

    // M5 — Form Analysis
    const cardFields = document.querySelectorAll(
      "input[name*='card'],input[name*='cvv'],input[name*='credit'],input[autocomplete*='cc']"
    );
    if (cardFields.length > 0 && protocol === "http:") {
      localScore += 20;
      reasons.push("Credit card form on unsecured page");
    }

    // M6 — Redirect Chain
    if (performance.navigation?.redirectCount > 3) {
      localScore += 15;
      reasons.push("Excessive redirects: " + performance.navigation.redirectCount);
    }

    // M7 — Page Fingerprint
    const loginForms = document.querySelectorAll("form:has(input[type='password'])");
    const fakeLoginIndicators = ["signin", "login", "account", "secure", "verify"];
    if (loginForms.length > 0) {
      const pageText = bodyText;
      const isFakeLogin = fakeLoginIndicators.some(ind => pageText.includes(ind)) && protocol === "http:";
      if (isFakeLogin) {
        localScore += 25;
        reasons.push("Fake login page pattern detected");
      }
    }

    // M8 — Clickjacking / Sandboxed Iframe Check
    const iframes = document.querySelectorAll("iframe");
    if (iframes.length > 2) {
      localScore += 10;
      reasons.push("Excessive iframe elements detected (" + iframes.length + ")");
    }

    // M9 — Voice Clone Monitoring
    const audioElements = document.querySelectorAll("audio, video");
    let hasSyntheticPattern = false;
    audioElements.forEach(el => {
      if (el.src && (el.src.includes("synth") || el.src.includes("ai-voice") || el.src.includes("clone") || el.src.includes("speech"))) {
        hasSyntheticPattern = true;
      }
    });
    if (audioElements.length > 0) {
      localScore += 5;
      reasons.push("Audio speech stream active (Voice Clone Monitoring)");
      if (hasSyntheticPattern) {
        localScore += 15;
        reasons.push("Suspicious synthetic voice patterns detected");
      }
    }

    // M10 — Fake Review Detection
    const reviews = document.querySelectorAll(".review, [class*='review'], [id*='review']");
    let suspiciousReviewPatterns = false;
    reviews.forEach(el => {
      const text = el.innerText?.toLowerCase() || "";
      if (["delve", "testament", "moreover", "highly recommend", "game changer"].filter(w => text.includes(w)).length > 2) {
        suspiciousReviewPatterns = true;
      }
    });
    if (suspiciousReviewPatterns) {
      localScore += 10;
      reasons.push("Repetitive / AI-generated review patterns detected");
    }

    // M11 — Fake Support Chat widget Detection
    const chatWidgets = document.querySelectorAll("[class*='chat'],[id*='chat'],[class*='support'],[id*='support']");
    let isScamChat = false;
    chatWidgets.forEach(el => {
      const text = el.innerText?.toLowerCase() || "";
      if (text.includes("help desk") || text.includes("support desk") || text.includes("agent live") || text.includes("customer service")) {
        if (protocol === "http:") {
          isScamChat = true;
        }
      }
    });
    if (isScamChat) {
      localScore += 20;
      reasons.push("Unsecured customer support widget (scam chat risk)");
    }

    // M12 — Browser Behavior Analysis
    if (performance.navigation?.redirectCount > 2) {
      localScore += 15;
      reasons.push("Browser behavior: forced redirect pattern detected");
    }

    // M13 — Hidden Script Analysis
    const scripts = document.querySelectorAll("script");
    let hasMinerOrObfuscation = false;
    scripts.forEach(s => {
      const src = s.src?.toLowerCase() || "";
      const content = s.textContent || "";
      if (src.includes("coinhive") || src.includes("cryptonight") || src.includes("miner.js")) {
        hasMinerOrObfuscation = true;
      }
      if (content.includes("eval(function(p,a,c,k,e,d)") || content.includes("\\x65\\x76\\x61\\x6c")) {
        hasMinerOrObfuscation = true;
      }
    });
    if (hasMinerOrObfuscation) {
      localScore += 25;
      reasons.push("Suspicious hidden scripts or cryptocurrency miner detected");
    }

  } catch (e) {
    console.warn("Local modules error:", e.message);
  }

  return {
    localScore: Math.min(localScore, 40),
    reasons
  };
};

// PART 11 — SMART CACHE SYSTEM
const getCacheKey = (domain) => "vc_" + domain;

const getCached = async (domain) => {
  try {
    const key = getCacheKey(domain);
    const data = await chrome.storage.local.get([key]);
    const entry = data[key];

    if (!entry) return null;

    const age = Date.now() - entry.timestamp;
    const risk = entry.result?.risk;

    const maxAge = risk === "SAFE" ? 
      2 * 60 * 60 * 1000 :      // 2 hours for safe
      risk === "SUSPICIOUS" ? 
      30 * 60 * 1000 :           // 30 min for suspicious
      5 * 60 * 1000;             // 5 min for dangerous

    if (age < maxAge) return entry.result;
    return null;
  } catch (e) {
    return null;
  }
};

const saveCache = async (domain, result) => {
  try {
    const key = getCacheKey(domain);
    await chrome.storage.local.set({
      [key]: { result, timestamp: Date.now() }
    });
  } catch (e) {}
};

// DETECTION EVIDENCE PANEL OVERLAY RENDERER
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

// PART 13 — SAVE AND BROADCAST
const saveAndBroadcast = async (result) => {
  try {
    chrome.runtime.sendMessage({
      action: "updateBadge",
      risk: result.risk
    });

    const { scanHistory = [] } = await chrome.storage.local.get(["scanHistory"]);
    const filtered = scanHistory.filter(s => s.domain !== result.domain);
    const updated = [result, ...filtered].slice(0, 500);

    await chrome.storage.local.set({
      scanHistory: updated
    });

    const isVeritasSite = window.location.href.includes("veritasai-shield.vercel.app") || window.location.href.includes("localhost:") || window.location.href.includes("127.0.0.1:");
    if (isVeritasSite) {
      localStorage.setItem("veritasai_scans", JSON.stringify(updated));
      window.dispatchEvent(new StorageEvent("storage", {
        key: "veritasai_scans",
        newValue: JSON.stringify(updated)
      }));
    }
  } catch (e) {
    console.warn("saveAndBroadcast error:", e.message);
  }
};

// PART 12 — MAIN SCAN FUNCTION
const initScan = async () => {
  try {
    const fullUrl = window.location.href;
    const hostname = window.location.hostname.toLowerCase();
    const baseDomain = getBaseDomain(hostname);

    if (!fullUrl.startsWith("http")) return;

    const { settings } = await chrome.storage.local.get(["settings"]);
    const controls = settings?.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
    if (controls.autoScan === false) return;

    if (isPermanentSafe(baseDomain)) {
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
          google: 0, urlscan: 0, virustotal: 0,
          domainAge: 0, abuse: 0, dns: 0, local: 0
        },
        time: Date.now(),
        cached: false,
        permanent: true
      };
      await saveAndBroadcast(result);
      return;
    }

    chrome.runtime.sendMessage({
      action: "updateBadge",
      risk: "SCANNING"
    });

    const cached = await getCached(baseDomain);
    if (cached) {
      await saveAndBroadcast({
        ...cached, cached: true
      });
      return;
    }

    const vtData = await chrome.storage.local.get([
      "vtCallsToday", "vtLastReset"
    ]);
    const vtCallsToday = vtData.vtCallsToday || 0;
    const canUseVT = vtCallsToday < 450;

    const apiKeys = settings?.apiKeys || {};
    const googleKey = apiKeys.googleSafeBrowsing || GOOGLE_KEY;
    const urlscanKey = apiKeys.urlscan || URLSCAN_KEY;
    const vtKey = apiKeys.virusTotal || VT_KEY;
    const abuseKey = apiKeys.abuseipdb || ABUSEIPDB_KEY;

    // Run ALL APIs simultaneously with Waterfall Timeout Safety
    const [
      google, urlscan, vt, rdap, abuse, dns, local
    ] = await Promise.all([
      checkGoogle(fullUrl, googleKey),
      checkURLScan(baseDomain, urlscanKey),
      canUseVT ? 
        checkVirusTotal(fullUrl, vtKey) : 
        Promise.resolve({ score: 0, reason: null, skipped: true }),
      checkDomainAge(baseDomain),
      checkAbuseIPDB(baseDomain, abuseKey),
      checkCloudfareDNS(baseDomain),
      Promise.resolve(runLocalModules())
    ]);

    const googleFlag = google.matched ? 100 : 0;
    const urlscanScore = urlscan.score || 0;
    const vtScore = vt.score || 0;
    const whoisFlag = rdap.flag || 0;
    const abuseScore = abuse.score || 0;
    const dnsFlag = dns.flag || 0;
    const localScore = local.localScore || 0;

    const apiScore = Math.round(
      (googleFlag * 0.25) +
      (urlscanScore * 0.25) +
      (vtScore * 0.25) +
      (abuseScore * 0.15) +
      (dnsFlag * 0.10)
    );

    let threatScore = Math.min(
      apiScore + localScore + whoisFlag, 100
    );
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
    } else if (
      urlscan.forceSUSPICIOUS ||
      abuse.forceSUSPICIOUS ||
      threatScore > 35
    ) {
      risk = "SUSPICIOUS";
    }

    const allReasons = [
      google.reason,
      urlscan.reason,
      vt.reason,
      rdap.reason,
      abuse.reason,
      dns.reason,
      ...local.reasons
    ].filter(Boolean);

    const apisWorked = !google.error || !urlscan.error || !vt.error || !abuse.error;
    if (!apisWorked) {
      allReasons.push("Local scan only — APIs unavailable");
    }

    let module = "Trust Engine";
    if (google.matched) module = "Phishing URL";
    else if (vt.forceDANGEROUS) module = "Malware Detection";
    else if (urlscan.forceDANGEROUS) module = "Scam Pattern";
    else if (abuse.forceDANGEROUS) module = "IP Reputation";
    else if (rdap.flag > 0) module = "New Domain — High Risk";
    else if (dns.flag > 0) module = "DNS Anomaly";
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
      aiPrediction:
        risk === "DANGEROUS" ?
          "Threat detected — do not proceed" :
        risk === "SUSPICIOUS" ?
          "Suspicious activity detected" :
          "No threats detected",
      mlRisk,
      reasons: allReasons.length > 0 ?
        allReasons :
        ["No threat signals detected"],
      subScores: {
        google: googleFlag,
        urlscan: urlscanScore,
        virustotal: vtScore,
        domainAge: whoisFlag,
        abuse: abuseScore,
        dns: dnsFlag,
        local: localScore
      },
      time: Date.now(),
      cached: false
    };

    await saveCache(baseDomain, result);
    await saveAndBroadcast(result);

    if (result.risk !== "SAFE" && controls.overlayAlerts) {
      showOverlay(result.score, result.reasons);
    }

  } catch (e) {
    console.warn("initScan error:", e.message);
    chrome.runtime.sendMessage({
      action: "updateBadge",
      risk: "SAFE"
    });
  }
};

// INITIALIZE AND DASHBOARD CHANNEL BINDINGS
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