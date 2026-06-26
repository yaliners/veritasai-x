const GOOGLE_SAFE_BROWSING_KEY = "AIzaSyAhlLFE9g0jR7wVbq-pRTMyAYRRLhfwrWs";
const IPQS_KEY = "sYnwTP8nMlIBGLK8dCXbUyDQEwQSXCiO";
const VIRUSTOTAL_KEY = "f50bfa739b08364404699b51bc26f326b2923a20222007b179e8b2b048a486e8";
const WHOIS_KEY = "at_XlkBiABAXaNSHT8KMsLEGgnssnVc2";

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

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error("timeout")), ms)
    )
  ]);
}

async function checkGoogleSafeBrowsing(url, googleKey) {
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
}

async function checkIPQualityScore(url, ipqsKey) {
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
}

async function checkVirusTotal(url, vtKey) {
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
}

async function checkWhoisAge(domain, whoisKey) {
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
}

function runLocalModules() {
  let localScore = 0;
  const reasons = [];
  
  if (window.location.protocol === "http:") {
    localScore += 25;
    reasons.push("No HTTPS encryption detected");
  }
  
  const host = window.location.hostname || currentSite;
  
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    localScore += 30;
    reasons.push("IP address used instead of domain name");
  }
  
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    localScore += 15;
    reasons.push(`Suspicious domain with ${hyphenCount} hyphens`);
  }
  
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
  
  if (host.length > 30) {
    localScore += 10;
    reasons.push(`Unusually long domain name (${host.length} characters)`);
  }
  
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
  
  return { localScore: Math.min(localScore, 40), reasons };
}

async function classifyAsync(url, title = "") {
  let host = ""; 
  try { host = new URL(url).hostname.toLowerCase(); } catch { host = url.toLowerCase(); }
  const baseDomain = host.replace(/^www\./, "");

  const { settings = {}, personalBlocklist = [], personalSafeList = [] } = await chrome.storage.local.get(["settings", "personalBlocklist", "personalSafeList"]);
  const modules = settings.modules || { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false };
  const apiKeys = settings.apiKeys || {};
  const googleKey = apiKeys.googleSafeBrowsing || GOOGLE_SAFE_BROWSING_KEY;
  const ipqsKey = apiKeys.ipQualityScore || IPQS_KEY;
  const vtKey = apiKeys.virusTotal || VIRUSTOTAL_KEY;
  const whoisKey = apiKeys.whoisXml || WHOIS_KEY;

  if (personalBlocklist.some(d => host === d || host.endsWith("." + d))) {
    return {
      host,
      risk: "DANGEROUS",
      score: 95,
      trust: 5,
      conf: 95,
      reasons: ["User reported dangerous domain"],
      modules: { phishing: 95, scam: 20, ai: 85, dark: 10, trust: 5 },
      module: "User Reported"
    };
  }

  if (personalSafeList.some(d => host === d || host.endsWith("." + d))) {
    return {
      host,
      risk: "SAFE",
      score: 0,
      trust: 100,
      conf: 100,
      reasons: ["User verified safe domain"],
      modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
      module: "User Verified"
    };
  }

  let googleResult = null;
  let ipqsResult = null;
  let vtResult = null;
  let whoisResult = null;

  try {
    const results = await Promise.all([
      modules.phishing ? withTimeout(checkGoogleSafeBrowsing(url, googleKey), 3000) : Promise.resolve(null),
      modules.scam ? withTimeout(checkIPQualityScore(url, ipqsKey), 3000) : Promise.resolve(null),
      withTimeout(checkVirusTotal(url, vtKey), 3000),
      withTimeout(checkWhoisAge(baseDomain, whoisKey), 3000)
    ]);
    googleResult = results[0];
    ipqsResult = results[1];
    vtResult = results[2];
    whoisResult = results[3];
  } catch (e) {}

  const allApisFailed = (googleResult === null && ipqsResult === null && vtResult === null && whoisResult === null);
  const reasons = [];

  const { localScore, reasons: localReasons } = runLocalModules();

  let threatScore = 0;
  let mlConfidence = "";

  const googleFlag = (googleResult && googleResult.matched) ? 100 : 0;
  const ipqsScore = ipqsResult ? (ipqsResult.score || 0) : 0;
  const vtScore = vtResult ? (vtResult.score || 0) : 0;
  const domainAgeFlag = (whoisResult && whoisResult.flag) ? whoisResult.flag : 0;

  if (allApisFailed) {
    threatScore = localScore;
    mlConfidence = "Local scan";
    reasons.push("Local scan only — APIs unavailable");
  } else {
    const baseScore = Math.max(googleFlag, ipqsScore, vtScore);
    threatScore = Math.max(baseScore, localScore, domainAgeFlag);
    threatScore = Math.min(100, Math.round(threatScore));
    mlConfidence = Math.round(threatScore) + "%";
  }

  threatScore = Math.min(100, threatScore);
  const trustScore = 100 - threatScore;

  let risk = "SAFE";
  const gsbMatched = (googleResult && googleResult.matched);
  const ipqsPhish = (ipqsResult && ipqsResult.forceDANGEROUS);
  const vtMalicious = (vtResult && vtResult.forceDANGEROUS);

  if (gsbMatched || ipqsPhish || vtMalicious || threatScore > 70) {
    risk = "DANGEROUS";
  } else if ((ipqsResult && ipqsResult.forceSUSPICIOUS) || threatScore > 35) {
    risk = "SUSPICIOUS";
  }

  let moduleName = "Trust Engine";
  if (gsbMatched) moduleName = "Phishing URL";
  else if (vtMalicious) moduleName = "Malware Detection";
  else if (ipqsResult && ipqsResult.forceDANGEROUS) moduleName = "Scam Pattern";
  else if (whoisResult && whoisResult.flag > 0) moduleName = "New Domain";
  else if (localScore > 20) moduleName = "Content NLP";

  if (googleResult && googleResult.reason) reasons.push(googleResult.reason);
  if (ipqsResult && ipqsResult.reason) reasons.push(ipqsResult.reason);
  if (vtResult && vtResult.reason) reasons.push(vtResult.reason);
  if (whoisResult && whoisResult.reason) reasons.push(whoisResult.reason);
  reasons.push(...localReasons);

  if (reasons.length === 0) {
    reasons.push("No threat signals detected");
  }

  return {
    host,
    risk,
    score: Math.round(threatScore),
    trust: Math.round(trustScore),
    conf: Math.round(threatScore),
    reasons,
    modules: {
      phishing: Math.min(100, Math.max(googleFlag, vtScore)),
      scam: Math.min(100, Math.max(ipqsScore, domainAgeFlag)),
      ai: 0,
      dark: 0,
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
        google: (modules.phishing || 0) > 90 ? 100 : 0,
        ipqs: (modules.scam || 0) > 90 ? 100 : 0,
        virustotal: result.module === "Malware Detection" ? 100 : 0,
        domainAge: result.module === "New Domain" ? 30 : 0,
        local: result.score - ((modules.phishing || 0) > 90 ? 25 : 0)
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

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0]?.url || "about:blank";
  const title = tabs[0]?.title || "";
  let host = "about:blank";
  try { host = new URL(url).hostname.toLowerCase(); } catch {}
  currentSite = host;
  currentUrl = url;

  const baseDomain = host.replace(/^www\./, "");
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
          subScores: { google: 0, ipqs: 0, virustotal: 0, domainAge: 0, local: 0 },
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
          subScores: { google: 0, ipqs: 0, virustotal: 0, domainAge: 0, local: 0 },
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