// PART 1 — API KEYS (Aligned with content.js)
const GOOGLE_KEY = "AIzaSyAhlLFE9g0jR7wVbq-pRTMyAYRRLhfwrWs";
const URLSCAN_KEY = "019eea96-036b-7407-8e7e-85df59cadb59";
const VT_KEY = "f50bfa739b08364404699b51bc26f326b2923a20222007b179e8b2b048a486e8";
const ABUSEIPDB_KEY = "9a65e7002cb5ebb9e4b39056277a24ac54f33afdf904a7bd6d79bfc4c0be7f2dcfd0433822434cd9";

let currentSite = "";
let currentUrl = "";

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

// API calls identical to content.js
const checkGoogle = async (url, googleKey) => {
  try {
    const activeKey = googleKey || GOOGLE_KEY;
    const res = await withTimeout(fetch(
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + activeKey,
      {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          client: { clientId: "veritasai", clientVersion: "3.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    ), 3000);

    if (!res.ok) return { score: 0, matched: false, reason: null, error: true };
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
    return { score: 0, matched: false, reason: null, error: true };
  }
};

const checkURLScan = async (domain, urlscanKey) => {
  try {
    const activeKey = urlscanKey || URLSCAN_KEY;
    const headers = {};
    if (activeKey) headers["API-Key"] = activeKey;

    const res = await withTimeout(fetch(
      "https://urlscan.io/api/v1/search/?q=domain:" + encodeURIComponent(domain) + "&size=1",
      { headers }
    ), 3000);

    if (!res.ok) return { score: 0, reason: null, error: true };
    const data = await res.json();
    const result = data.results?.[0];

    if (!result) return { score: 0, reason: null };
    const verdicts = result.verdicts?.overall;
    const malicious = verdicts?.malicious || false;
    const score = verdicts?.score || 0;

    return {
      score: malicious ? 100 : score,
      malicious,
      reason: malicious ? "URLScan flagged as malicious" : score > 50 ? "URLScan suspicious score: " + score : null,
      forceDANGEROUS: malicious,
      forceSUSPICIOUS: !malicious && score > 50
    };
  } catch (e) {
    return { score: 0, reason: null, error: true };
  }
};

const checkVirusTotal = async (url, vtKey) => {
  if (!canCallVT()) return { score: 0, reason: null, skipped: true };

  try {
    vtLastCall = Date.now();
    const activeKey = vtKey || VT_KEY;
    const urlId = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

    const res = await withTimeout(fetch(
      "https://www.virustotal.com/api/v3/urls/" + urlId,
      { headers: { "x-apikey": activeKey } }
    ), 3000);

    if (res.status === 404) {
      const submitRes = await withTimeout(fetch(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: { "x-apikey": activeKey, "Content-Type": "application/x-www-form-urlencoded" },
          body: "url=" + encodeURIComponent(url)
        }
      ), 3000);

      if (!submitRes.ok) return { score: 0, malicious: 0, reason: null };
      const submitData = await submitRes.json();
      const analysisId = submitData.data?.id;

      if (!analysisId) return { score: 0, malicious: 0, reason: null };
      const pollRes = await withTimeout(fetch(
        "https://www.virustotal.com/api/v3/analyses/" + analysisId,
        { headers: { "x-apikey": activeKey } }
      ), 3000);

      if (!pollRes.ok) return { score: 0, malicious: 0, reason: null };
      const pollData = await pollRes.json();
      const stats = pollData.data?.attributes?.stats || {};
      const malicious = stats.malicious || 0;
      const total = (stats.malicious || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0);

      await incrementVTCounter();
      return {
        score: malicious > 3 ? 100 : malicious * 20,
        malicious,
        total,
        reason: malicious > 0 ? malicious + "/" + total + " antivirus engines flagged" : null,
        forceDANGEROUS: malicious > 3
      };
    }

    if (!res.ok) return { score: 0, malicious: 0, reason: null, error: true };
    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const total = (stats.malicious || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0);

    await incrementVTCounter();
    return {
      score: malicious > 3 ? 100 : malicious * 20,
      malicious,
      total,
      reason: malicious > 0 ? malicious + "/" + total + " antivirus engines flagged" : null,
      forceDANGEROUS: malicious > 3
    };
  } catch (e) {
    return { score: 0, malicious: 0, reason: null, error: true };
  }
};

const checkDomainAge = async (domain) => {
  try {
    const res = await withTimeout(fetch(
      "https://rdap.org/domain/" + domain
    ), 3000);

    if (!res.ok) return { flag: 0, ageDays: null, reason: null };
    const data = await res.json();
    const regEvent = data.events?.find(e => e.eventAction === "registration");

    if (!regEvent) return { flag: 0, ageDays: null, reason: null };
    const regDate = new Date(regEvent.eventDate);
    const ageDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));

    const flag = ageDays < 30 ? 30 : ageDays < 90 ? 15 : 0;
    const reason = ageDays < 30 ? "Domain only " + ageDays + " days old — very high risk" :
                   ageDays < 90 ? "Domain " + ageDays + " days old — relatively new" : null;

    return { ageDays, flag, reason };
  } catch (e) {
    return { flag: 0, ageDays: null, reason: null };
  }
};

const checkAbuseIPDB = async (domain, abuseKey) => {
  try {
    const activeKey = abuseKey || ABUSEIPDB_KEY;
    const res = await withTimeout(fetch(
      "https://api.abuseipdb.com/api/v2/check?ipAddress=" + encodeURIComponent(domain) + "&maxAgeInDays=90",
      {
        headers: { "Key": activeKey, "Accept": "application/json" }
      }
    ), 3000);

    if (!res.ok) return { score: 0, reason: null, error: true };
    const data = await res.json();
    const score = data.data?.abuseConfidenceScore || 0;

    return {
      score,
      reason: score > 40 ? "AbuseIPDB confidence: " + score + "%" : null,
      forceDANGEROUS: score > 80,
      forceSUSPICIOUS: score > 40
    };
  } catch (e) {
    return { score: 0, reason: null, error: true };
  }
};

const checkCloudfareDNS = async (domain) => {
  try {
    const res = await withTimeout(fetch(
      "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(domain) + "&type=A",
      { headers: { "Accept": "application/dns-json" } }
    ), 3000);

    if (!res.ok) return { flag: 0, reason: null, error: true };
    const data = await res.json();
    const status = data.Status;
    const hasAnswers = data.Answer?.length > 0;

    if (status !== 0 || !hasAnswers) {
      return { flag: 20, reason: "DNS anomaly detected — domain may not resolve properly" };
    }
    return { flag: 0, reason: null };
  } catch (e) {
    return { flag: 0, reason: null, error: true };
  }
};

// URL heuristics matching content.js context (avoiding browser DOM dependency)
const runLocalModules = (url, host) => {
  let localScore = 0;
  const reasons = [];
  const protocol = url.startsWith("https") ? "https:" : "http:";

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
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".click", ".top", ".gq", ".pw",
    ".work", ".loan", ".date", ".racing", ".win", ".download", ".stream",
    ".party", ".review"
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
    "paypa1", "amaz0n", "g00gle", "app1e", "faceb00k", "netfl1x", "lnstagram", "tw1tter", "micros0ft", "paypai"
  ];
  homoglyphs.forEach(h => {
    if (host.includes(h)) {
      localScore += 35;
      reasons.push("Brand impersonation detected: " + h);
    }
  });

  if (protocol === "http:") {
    localScore += 25;
    reasons.push("No HTTPS encryption");
  }

  return {
    localScore: Math.min(localScore, 40),
    reasons
  };
};

async function classifyAsync(url, title = "") {
  let host = "";
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    host = url.toLowerCase();
  }
  const baseDomain = getBaseDomain(host);

  const { settings = {} } = await chrome.storage.local.get(["settings"]);
  const apiKeys = settings.apiKeys || {};

  const googleKey = apiKeys.googleSafeBrowsing || GOOGLE_KEY;
  const urlscanKey = apiKeys.urlscan || URLSCAN_KEY;
  const vtKey = apiKeys.virusTotal || VT_KEY;
  const abuseKey = apiKeys.abuseipdb || ABUSEIPDB_KEY;

  const [google, urlscan, vt, rdap, abuse, dns] = await Promise.all([
    checkGoogle(url, googleKey),
    checkURLScan(baseDomain, urlscanKey),
    checkVirusTotal(url, vtKey),
    checkDomainAge(baseDomain),
    checkAbuseIPDB(baseDomain, abuseKey),
    checkCloudfareDNS(baseDomain)
  ]);

  const { localScore, reasons: localReasons } = runLocalModules(url, baseDomain);

  const googleFlag = google.matched ? 100 : 0;
  const urlscanScore = urlscan.score || 0;
  const vtScore = vt.score || 0;
  const whoisFlag = rdap.flag || 0;
  const abuseScore = abuse.score || 0;
  const dnsFlag = dns.flag || 0;

  const apiScore = Math.round(
    (googleFlag * 0.25) +
    (urlscanScore * 0.25) +
    (vtScore * 0.25) +
    (abuseScore * 0.15) +
    (dnsFlag * 0.10)
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
    ...localReasons
  ].filter(Boolean);

  const apisWorked = !google.error || !urlscan.error || !vt.error || !abuse.error;
  if (!apisWorked) {
    allReasons.push("Local scan only — APIs unavailable");
  }

  let moduleName = "Trust Engine";
  if (google.matched) moduleName = "Phishing URL";
  else if (vt.forceDANGEROUS) moduleName = "Malware Detection";
  else if (urlscan.forceDANGEROUS) moduleName = "Scam Pattern";
  else if (abuse.forceDANGEROUS) moduleName = "IP Reputation";
  else if (rdap.flag > 0) moduleName = "New Domain";
  else if (localScore > 20) moduleName = "Content NLP";

  return {
    host,
    risk,
    score: Math.round(threatScore),
    trust: Math.round(trustScore),
    conf: Math.round(threatScore),
    reasons: allReasons,
    modules: {
      phishing: Math.min(100, Math.max(googleFlag, vtScore)),
      scam: Math.min(100, Math.max(urlscanScore, abuseScore)),
      ai: 0,
      dark: Math.min(100, localScore),
      trust: Math.round(trustScore)
    },
    module: moduleName
  };
}

function renderLoading(host) {
  document.getElementById("domain").textContent = host;
  const badge = document.getElementById("riskBadge");
  badge.textContent = "SCANNING...";
  badge.className = "badge";
  badge.style.background = "rgba(107, 122, 153, 0.15)";
  badge.style.color = "#6b7a99";
  badge.style.borderColor = "rgba(107, 122, 153, 0.4)";
  
  document.getElementById("threat").textContent = "--";
  document.getElementById("trust").textContent = "--";
  document.getElementById("conf").textContent = "--";
  
  const defaultModules = ["Phishing URL", "Scam Pattern", "AI Content", "Dark Pattern", "Trust Engine"];
  document.getElementById("modules").innerHTML = defaultModules.map((m) => {
    return `<li><span>${m}</span><span style="color:#6b7a99;">Checking...</span></li>`;
  }).join("");
  
  document.getElementById("reasons").innerHTML = `<li>Scanning page for security vulnerabilities...</li>`;
}

function render(r, isCached = false) {
  document.getElementById("domain").textContent = r.host;
  const badge = document.getElementById("riskBadge");
  badge.textContent = r.risk === "TRUSTED" ? "SAFE" : r.risk;
  badge.className = "badge " + (r.risk === "TRUSTED" ? "safe" : r.risk.toLowerCase());
  badge.removeAttribute("style");

  document.getElementById("threat").textContent = r.score;
  document.getElementById("trust").textContent = r.trust;
  document.getElementById("conf").textContent = r.conf + "%";

  const scanStatusEl = document.getElementById("scanStatus");
  if (scanStatusEl) {
    if (isCached) {
      scanStatusEl.textContent = "LIVE (cached)";
      scanStatusEl.style.background = "rgba(245, 158, 11, 0.12)";
      scanStatusEl.style.color = "#f59e0b";
      scanStatusEl.style.borderColor = "rgba(245, 158, 11, 0.3)";
    } else {
      scanStatusEl.textContent = "LIVE";
      scanStatusEl.style.background = "rgba(34, 197, 94, 0.12)";
      scanStatusEl.style.color = "#22c55e";
      scanStatusEl.style.borderColor = "rgba(34, 197, 94, 0.3)";
      scanStatusEl.removeAttribute("style");
    }
  }

  const modules = r.modules || { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 };
  const mods = [
    { name: "Phishing URL", v: modules.phishing !== undefined ? modules.phishing : 0 },
    { name: "Scam Pattern", v: modules.scam !== undefined ? modules.scam : 0 },
    { name: "AI Content", v: modules.ai !== undefined ? modules.ai : 0 },
    { name: "Dark Pattern", v: modules.dark !== undefined ? modules.dark : 0 },
    { name: "Trust Engine", v: modules.trust !== undefined ? modules.trust : 100 },
  ];
  document.getElementById("modules").innerHTML = mods.map((m) => {
    const cls = m.name === "Trust Engine" ? (m.v > 70 ? "ok" : m.v > 40 ? "warn" : "bad") : (m.v > 60 ? "bad" : m.v > 30 ? "warn" : "ok");
    return `<li><span>${m.name}</span><span class="${cls}">${m.v}</span></li>`;
  }).join("");

  const hasLocalOnly = (r.reasons || []).some(x => x.includes("Local scan only"));

  if (r.risk === "DANGEROUS" || r.risk === "SUSPICIOUS") {
    const evidenceListHtml = (r.reasons || [])
      .filter((x) => !x.includes("Local scan only"))
      .slice(0, 6)
      .map((x) => {
        const cleanText = x.replace(/^[✓\s*-]+/, "");
        return `<li style="font-size: 11px; color: #e6edf7; padding: 0; display: flex; align-items: flex-start; gap: 6px; line-height: 1.4; margin-bottom: 4px; text-align: left;">
          <span style="color: #22c55e; font-weight: bold; shrink-0;">✓</span>
          <span>${cleanText}</span>
        </li>`;
      }).join("");

    document.getElementById("reasons").innerHTML = `
      <div style="background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 12px; margin-top: 4px; text-align: left; width: 100%;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(239, 68, 68, 0.15); padding-bottom: 8px; margin-bottom: 8px;">
          <span style="font-size: 11px; font-weight: 700; color: #ef4444; text-transform: uppercase; letter-spacing: 0.05em;">Evidence</span>
          <div style="display: flex; gap: 4px; align-items: center;">
            ${hasLocalOnly ? `<span style="font-size: 9px; font-weight: 700; color: #f59e0b; background: rgba(245, 158, 11, 0.12); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.3);">Local scan only</span>` : ''}
            <span style="font-size: 11px; font-weight: 700; color: #ef4444; background: rgba(239, 68, 68, 0.12); padding: 2px 6px; border-radius: 4px;">Threat Score: ${r.score || 0}</span>
          </div>
        </div>
        <ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px;">
          ${evidenceListHtml}
        </ul>
      </div>
    `;
  } else {
    let reasonsHtml = (r.reasons || []).slice(0, 5).map((x) => `<li>${x}</li>`).join("");
    if (hasLocalOnly) {
      reasonsHtml = `
        <div style="background: rgba(245, 158, 11, 0.05); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 8px; padding: 12px; margin-top: 4px; text-align: left; width: 100%;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(245, 158, 11, 0.15); padding-bottom: 8px; margin-bottom: 8px;">
            <span style="font-size: 11px; font-weight: 700; color: #f59e0b; text-transform: uppercase; letter-spacing: 0.05em;">AI Explanation</span>
            <span style="font-size: 9px; font-weight: 700; color: #f59e0b; background: rgba(245, 158, 11, 0.12); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.3);">Local scan only</span>
          </div>
          <ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px; font-size: 11px;">
            ${(r.reasons || []).filter(x => !x.includes("Local scan only")).map(x => `<li>${x}</li>`).join("")}
          </ul>
        </div>
      `;
    }
    document.getElementById("reasons").innerHTML = reasonsHtml;
  }
}

function renderPlaceholder(host) {
  document.getElementById("domain").textContent = host;
  const badge = document.getElementById("riskBadge");
  badge.textContent = "PENDING";
  badge.className = "badge suspicious";
  document.getElementById("threat").textContent = "—";
  document.getElementById("trust").textContent = "—";
  document.getElementById("conf").textContent = "—";
  document.getElementById("modules").innerHTML = `<li><span>Auto Scan is disabled.</span></li>`;
  document.getElementById("reasons").innerHTML = `<li>Click 'Scan Now' to run real-time threat intelligence scan.</li>`;
}

function saveAndRender(result, cacheKey, host, url, scanHistory) {
  if (url.startsWith("http://") || url.startsWith("https://")) {
    const modules = result.modules || { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 };
    const scanResult = {
      url: url,
      domain: host,
      risk: result.risk,
      score: result.score,
      trustScore: result.trust,
      mlConfidence: result.conf + "%",
      module: result.module,
      aiPrediction: result.risk === "DANGEROUS" ? "Threat detected — do not proceed" :
                    result.risk === "SUSPICIOUS" ? "Suspicious activity detected" :
                    "No threats detected",
      mlRisk: result.score > 70 ? "High" : result.score > 35 ? "Medium" : "Low",
      subScores: {
        google: result.subScores?.google || 0,
        urlscan: result.subScores?.urlscan || 0,
        virustotal: result.subScores?.virustotal || 0,
        domainAge: result.subScores?.domainAge || 0,
        abuse: result.subScores?.abuse || 0,
        dns: result.subScores?.dns || 0,
        local: result.subScores?.local || 0
      },
      time: Date.now(),
      cached: false,
      reasons: result.reasons,
      modules: modules,
      conf: result.conf
    };
    
    const filtered = scanHistory.filter(h => h.url !== url);
    const updatedHistory = [scanResult, ...filtered].slice(0, 500);
    chrome.storage.local.set({ scanHistory: updatedHistory });

    chrome.storage.local.set({
      [cacheKey]: {
        result: scanResult,
        timestamp: Date.now()
      }
    });
    updateStatsBar(updatedHistory);
  }
  render(result);
}

// Tab initiation
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0]?.url || "about:blank";
  const title = tabs[0]?.title || "";
  let host = "about:blank";
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {}
  currentSite = host;
  currentUrl = url;

  const baseDomain = getBaseDomain(host);
  const isPermanentSafe = PERMANENT_SAFE.some(
    safe => baseDomain === safe || baseDomain.endsWith("." + safe)
  );

  chrome.storage.local.get(["scanHistory", "settings", "trustedDomains"], async ({ scanHistory = [], settings = {}, trustedDomains = [] }) => {
    const controls = settings?.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
    const cacheKey = "vc_" + baseDomain;

    if (isPermanentSafe) {
      const result = {
        host: host,
        risk: "SAFE",
        score: 0,
        trust: 100,
        conf: 100,
        reasons: ["Verified trusted domain"],
        modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
        module: "Trust Engine"
      };
      render(result);
      saveAndRender(result, cacheKey, host, url, scanHistory);
      chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" });
      return;
    }

    chrome.storage.local.get([cacheKey], async (cachedData) => {
      const cacheEntry = cachedData[cacheKey];
      let result;

      if (cacheEntry && cacheEntry.timestamp && (Date.now() - cacheEntry.timestamp < 3600000)) {
        const cachedResult = cacheEntry.result;
        result = {
          host: cachedResult.domain,
          risk: cachedResult.risk,
          score: cachedResult.score,
          trust: cachedResult.trustScore,
          conf: cachedResult.conf || cachedResult.score,
          reasons: cachedResult.reasons,
          modules: cachedResult.modules,
          module: cachedResult.module
        };
        render(result, true);
        updateStatsBar(scanHistory);
      } else {
        renderLoading(host);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "SCANNING" });

        if (!controls.autoScan) {
          renderPlaceholder(host);
          updateStatsBar(scanHistory);
        } else {
          result = await classifyAsync(url, title);
          saveAndRender(result, cacheKey, host, url, scanHistory);
          chrome.runtime.sendMessage({ action: "updateBadge", risk: result.risk });
        }
      }
    });
  });
});

document.getElementById("scanNow").addEventListener("click", async () => {
  const btn = document.getElementById("scanNow");
  btn.textContent = "Scanning...";
  btn.disabled = true;

  try {
    renderLoading(currentSite);
    chrome.runtime.sendMessage({ action: "updateBadge", risk: "SCANNING" });
    const result = await classifyAsync(currentUrl, "");
    const cacheKey = "vc_" + currentSite.replace(/^www\./, "").toLowerCase();
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      saveAndRender(result, cacheKey, currentSite, currentUrl, scanHistory);
      chrome.runtime.sendMessage({ action: "updateBadge", risk: result.risk });
    });
  } catch (e) {
    console.error(e);
  } finally {
    btn.textContent = "Scan Now";
    btn.disabled = false;
  }
});

function updateStatsBar(history) {
  const total = history.length;
  const blocked = history.filter(x => x.risk === "DANGEROUS").length;
  const safe = history.filter(x => x.risk === "SAFE").length;

  document.getElementById("totalScanned").textContent = total;
  document.getElementById("threatsBlocked").textContent = blocked;
  document.getElementById("safeSites").textContent = safe;
}

document.getElementById("openDash").addEventListener("click", () => {
  chrome.tabs.create({ url: "https://veritasai-shield.vercel.app/dashboard" });
});

document.getElementById("reportDangerous").addEventListener("click", () => {
  chrome.storage.local.get(["personalBlocklist", "scanHistory"], ({ personalBlocklist = [], scanHistory = [] }) => {
    if (!personalBlocklist.includes(currentSite)) {
      personalBlocklist.push(currentSite);
    }
    chrome.storage.local.set({ personalBlocklist }, () => {
      const scanResult = {
        host: currentSite,
        risk: "DANGEROUS",
        score: 95,
        trust: 5,
        conf: 95,
        reasons: ["User reported dangerous domain"],
        modules: { phishing: 95, scam: 20, ai: 85, dark: 10, trust: 5 },
        module: "User Reported"
      };
      render(scanResult);

      if (currentUrl.startsWith("http://") || currentUrl.startsWith("https://")) {
        const cacheKey = "vc_" + currentSite.replace(/^www\./, "").toLowerCase();
        const historyScanResult = {
          url: currentUrl,
          domain: currentSite,
          risk: "DANGEROUS",
          score: 95,
          trustScore: 5,
          mlConfidence: "95%",
          module: "User Reported",
          aiPrediction: "Threat detected — do not proceed",
          mlRisk: "High",
          subScores: { google: 0, urlscan: 0, virustotal: 0, domainAge: 0, abuse: 0, dns: 0, local: 0 },
          time: Date.now(),
          cached: false,
          reasons: ["User reported dangerous domain"],
          modules: { phishing: 95, scam: 20, ai: 85, dark: 10, trust: 5 },
          conf: 95
        };
        const filtered = scanHistory.filter(h => h.url !== currentUrl);
        const updatedHistory = [historyScanResult, ...filtered].slice(0, 500);
        chrome.storage.local.set({ scanHistory: updatedHistory });
        chrome.storage.local.set({
          [cacheKey]: {
            result: historyScanResult,
            timestamp: Date.now()
          }
        });
        updateStatsBar(updatedHistory);
      }

      const btn = document.getElementById("reportDangerous");
      btn.textContent = "Marked as dangerous ✓";
      setTimeout(() => {
        btn.textContent = "🚨 Report Dangerous";
      }, 2000);

      chrome.runtime.sendMessage({ action: "updateBadge", risk: "DANGEROUS" });
    });
  });
});

document.getElementById("reportSafe").addEventListener("click", () => {
  chrome.storage.local.get(["personalSafeList", "scanHistory"], ({ personalSafeList = [], scanHistory = [] }) => {
    if (!personalSafeList.includes(currentSite)) {
      personalSafeList.push(currentSite);
    }
    chrome.storage.local.set({ personalSafeList }, () => {
      const scanResult = {
        host: currentSite,
        risk: "SAFE",
        score: 0,
        trust: 100,
        conf: 100,
        reasons: ["User verified safe domain"],
        modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
        module: "User Verified"
      };
      render(scanResult);

      if (currentUrl.startsWith("http://") || currentUrl.startsWith("https://")) {
        const cacheKey = "vc_" + currentSite.replace(/^www\./, "").toLowerCase();
        const historyScanResult = {
          url: currentUrl,
          domain: currentSite,
          risk: "SAFE",
          score: 0,
          trustScore: 100,
          mlConfidence: "100%",
          module: "User Verified",
          aiPrediction: "No threats detected",
          mlRisk: "Low",
          subScores: { google: 0, urlscan: 0, virustotal: 0, domainAge: 0, abuse: 0, dns: 0, local: 0 },
          time: Date.now(),
          cached: false,
          reasons: ["User verified safe domain"],
          modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
          conf: 100
        };
        const filtered = scanHistory.filter(h => h.url !== currentUrl);
        const updatedHistory = [historyScanResult, ...filtered].slice(0, 500);
        chrome.storage.local.set({ scanHistory: updatedHistory });
        chrome.storage.local.set({
          [cacheKey]: {
            result: historyScanResult,
            timestamp: Date.now()
          }
        });
        updateStatsBar(updatedHistory);
      }

      const btn = document.getElementById("reportSafe");
      btn.textContent = "Marked as safe ✓";
      setTimeout(() => {
        btn.textContent = "✅ Report Safe";
      }, 2000);

      chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" });
    });
  });
});