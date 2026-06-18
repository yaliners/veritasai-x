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
  "anthropic.com", "openai.com", "vercel.app",
  "veritasai-shield.vercel.app"
];


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
    return { matched: !!(data.matches && data.matches.length > 0) };
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

async function classifyAsync(url, title = "") {
  let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch { host = url.toLowerCase(); }
  const lowerUrl = url.toLowerCase();

  const { settings = {}, personalBlocklist = [], personalSafeList = [] } = await chrome.storage.local.get(["settings", "personalBlocklist", "personalSafeList"]);
  const modules = settings.modules || { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false };

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

  // 1. Permanent safe list check
  const isPermanentSafe = PERMANENT_SAFE.some(d => host === d || host.endsWith("." + d));
  if (isPermanentSafe) {
    return {
      host,
      risk: "TRUSTED",
      score: 0,
      trust: 100,
      conf: 100,
      reasons: ["Permanent safe listed domain"],
      modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
      module: "Trust Engine"
    };
  }


  // Run concurrent APIs
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
  } catch (e) {}

  const allApisFailed = (googleResult === null && ipqsResult === null && vtResult === null && whoisResult === null);
  const reasons = [];

  let M6_score = 0;
  let M8_score = 0;

  // SSL Check M6
  const isHttp = url.startsWith("http://");
  if (isHttp) {
    M6_score += 25;
    reasons.push("SSL Check: HTTP connection");
  }

  // URL analysis M8
  const isIpAddress = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes("[");
  if (isIpAddress) {
    M8_score += 30;
    reasons.push("URL Analysis: IP address used");
  }
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    M8_score += 15;
    reasons.push("URL Analysis: Domain has >2 hyphens");
  }
  const isSuspiciousTld = /\.(xyz|tk|ml|ga|cf|click|top|gq|pw|work)$/i.test(host);
  if (isSuspiciousTld) {
    M8_score += 20;
    reasons.push("URL Analysis: Suspicious TLD");
  }
  if (host.length > 30) {
    M8_score += 10;
    reasons.push("URL Analysis: Domain length > 30");
  }
  const isMixedBrand = /(?:paypa1|amaz0n|g00gle|micr0soft|github1|app1e|faceb00k|netf1ix|sp0tify)/i.test(host);
  if (isMixedBrand) {
    M8_score += 35;
    reasons.push("URL Analysis: Homoglyph brand detected");
  }

  const localScore = M6_score + M8_score;

  let threatScore = 0;
  let mlConfidence = "";

  const googleFlag = (googleResult && googleResult.matched) ? 100 : 0;
  const ipqsScore = ipqsResult ? (ipqsResult.fraud_score || 0) : 0;
  const vtScore = vtResult ? (vtResult.malicious > 3 ? 100 : vtResult.malicious * 20) : 0;
  const domainAgeFlag = (whoisResult && whoisResult.age < 30) ? 30 : 0;

  if (allApisFailed) {
    threatScore = localScore;
    mlConfidence = "Local scan";
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
  else if (M8_score > 0) moduleName = "Phishing URL";

  if (modules.voiceClone) {
    reasons.push("Beta — monitoring audio elements");
  }

  if (reasons.length === 0) {
    reasons.push("No malicious indicators detected");
  }

  return {
    host,
    risk,
    score: Math.round(threatScore),
    trust: Math.round(trustScore),
    conf: Math.round(threatScore),
    reasons,
    modules: {
      phishing: Math.min(100, Math.max(googleFlag, vtScore, M8_score)),
      scam: Math.min(100, Math.max(ipqsScore, domainAgeFlag, M6_score)),
      ai: 0,
      dark: 0,
      trust: Math.round(trustScore)
    },
    module: moduleName
  };
}

function render(r) {
  document.getElementById("domain").textContent = r.host;
  const badge = document.getElementById("riskBadge");
  badge.textContent = r.risk === "TRUSTED" ? "SAFE" : r.risk;
  badge.className = "badge " + (r.risk === "TRUSTED" ? "safe" : r.risk.toLowerCase());
  document.getElementById("threat").textContent = r.score;
  document.getElementById("trust").textContent = r.trust;
  document.getElementById("conf").textContent = r.conf + "%";

  const modules = r.modules || { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 };
  const mods = [
    { name: "Phishing", v: modules.phishing !== undefined ? modules.phishing : 0 },
    { name: "Scam", v: modules.scam !== undefined ? modules.scam : 0 },
    { name: "AI Content", v: modules.ai !== undefined ? modules.ai : 0 },
    { name: "Dark Pattern", v: modules.dark !== undefined ? modules.dark : 0 },
    { name: "Trust Engine", v: modules.trust !== undefined ? modules.trust : 100 },
  ];
  document.getElementById("modules").innerHTML = mods.map((m) => {
    const cls = m.name === "Trust Engine" ? (m.v > 70 ? "ok" : m.v > 40 ? "warn" : "bad") : (m.v > 60 ? "bad" : m.v > 30 ? "warn" : "ok");
    return `<li><span>${m.name}</span><span class="${cls}">${m.v}</span></li>`;
  }).join("");

  document.getElementById("reasons").innerHTML = (r.reasons || []).slice(0, 5).map((x) => `<li>${x}</li>`).join("");
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
      aiPrediction: result.risk === "DANGEROUS" ? "Malicious" : result.risk === "SUSPICIOUS" ? "Suspicious" : "Benign",
      mlRisk: result.score > 70 ? "High" : result.score > 35 ? "Medium" : "Low",
      subScores: {
        google: (modules.phishing || 0) > 90 ? 100 : 0,
        ipqs: (modules.scam || 0) > 90 ? 100 : 0,
        virustotal: result.module === "Malware Detection" ? 100 : 0,
        domainAge: result.module === "New Domain — High Risk" ? 30 : 0,
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

    // Save to cache vc_DOMAIN
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
  try { host = new URL(url).hostname; } catch {}
  currentSite = host;
  currentUrl = url;

  chrome.storage.local.get(["scanHistory", "settings", "trustedDomains"], async ({ scanHistory = [], settings = {}, trustedDomains = [] }) => {
    const controls = settings?.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
    const cacheKey = "vc_" + url;

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
        render(result);
        updateStatsBar(scanHistory);
      } else {
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
    const result = await classifyAsync(currentUrl, "");
    const cacheKey = "vc_" + currentUrl;
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
        const cacheKey = "vc_" + currentUrl;
        const historyScanResult = {
          url: currentUrl,
          domain: currentSite,
          risk: "DANGEROUS",
          score: 95,
          trustScore: 5,
          mlConfidence: "95%",
          module: "User Reported",
          aiPrediction: "Malicious",
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
        const cacheKey = "vc_" + currentUrl;
        const historyScanResult = {
          url: currentUrl,
          domain: currentSite,
          risk: "SAFE",
          score: 0,
          trustScore: 100,
          mlConfidence: "100%",
          module: "User Verified",
          aiPrediction: "Benign",
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