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

const DANGEROUS_BLOCKLIST = [
  "phishing.testing.google.test",
  "malware.testing.google.test",
  "testscam.html",
  "secure-paypal-login.net",
  "paypa1.com",
  "crypto-doubler.xyz",
  "freerobux-generator.xyz",
  "win-prize-now.click",
  "fake-bank-login.net",
  "amaz0n-orders-support.help"
];

const SUSPICIOUS_BLOCKLIST = [
  "netmirror.org",
  "crackingpatching.com",
  "softonic.com",
  "fmovies.to",
  "opensubtitles.org",
  "testphp.vulnweb.com",
  "testfire.net",
  "zero.webappsecurity.com"
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

  // 2. Blocklist check
  const isDangerousDomain = DANGEROUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
  const isSuspiciousDomain = SUSPICIOUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));

  if (isDangerousDomain) {
    return {
      host,
      risk: "DANGEROUS",
      score: 95,
      trust: 5,
      conf: 95,
      reasons: ["Blacklisted dangerous domain"],
      modules: { phishing: 95, scam: 20, ai: 85, dark: 10, trust: 5 },
      module: "Blocklist"
    };
  }

  if (isSuspiciousDomain) {
    return {
      host,
      risk: "SUSPICIOUS",
      score: 65,
      trust: 35,
      conf: 65,
      reasons: ["Blacklisted suspicious domain"],
      modules: { phishing: 65, scam: 15, ai: 50, dark: 10, trust: 35 },
      module: "Blocklist"
    };
  }

  // Run concurrent APIs
  let googleResult = null;
  let ipqsResult = null;
  let vtResult = null;
  let whoisResult = null;

  try {
    const results = await Promise.all([
      withTimeout(checkGoogleSafeBrowsing(url, GOOGLE_SAFE_BROWSING_KEY), 3000),
      withTimeout(checkIPQualityScore(url, IPQS_KEY), 3000),
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
    const baseScore = (googleFlag * 0.25) + (ipqsScore * 0.40) + (vtScore * 0.35);
    threatScore = baseScore + localScore + domainAgeFlag;
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
  else if (vtMalicious) moduleName = "Malware Detection";
  else if (ipqsPhish) moduleName = "Scam Pattern";
  else if (whoisResult && whoisResult.age < 30) moduleName = "New Domain — High Risk";
  else if (M6_score > 0) moduleName = "SSL Check";
  else if (M8_score > 0) moduleName = "URL Analysis";

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
      phishing: gsbMatched ? 100 : (risk === "DANGEROUS" ? 90 : 10),
      scam: ipqsPhish ? 100 : 10,
      ai: Math.round(threatScore * 0.8),
      dark: 10,
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

  const mods = [
    { name: "Phishing", v: r.modules.phishing },
    { name: "Scam", v: r.modules.scam },
    { name: "AI Content", v: r.modules.ai },
    { name: "Dark Pattern", v: r.modules.dark },
    { name: "Trust Engine", v: r.modules.trust },
  ];
  document.getElementById("modules").innerHTML = mods.map((m) => {
    const cls = m.name === "Trust Engine" ? (m.v > 70 ? "ok" : m.v > 40 ? "warn" : "bad") : (m.v > 60 ? "bad" : m.v > 30 ? "warn" : "ok");
    return `<li><span>${m.name}</span><span class="${cls}">${m.v}</span></li>`;
  }).join("");

  document.getElementById("reasons").innerHTML = r.reasons.slice(0, 5).map((x) => `<li>${x}</li>`).join("");
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0]?.url || "about:blank";
  const title = tabs[0]?.title || "";
  let host = "about:blank";
  try { host = new URL(url).hostname; } catch {}

  chrome.storage.local.get(["scanHistory", "settings", "trustedDomains"], async ({ scanHistory = [], settings = {}, trustedDomains = [] }) => {
    // Check cache:vc_DOMAIN first
    const cacheKey = "vc_" + host;
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
      } else {
        // Fallback to async classification
        result = await classifyAsync(url, title);
        
        // Save scan result to scanHistory if it is a real page
        if (url.startsWith("http://") || url.startsWith("https://")) {
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
              google: result.modules.phishing > 90 ? 100 : 0,
              ipqs: result.modules.scam > 90 ? 100 : 0,
              virustotal: result.module === "Malware Detection" ? 100 : 0,
              domainAge: result.module === "New Domain — High Risk" ? 30 : 0,
              local: result.score - (result.modules.phishing > 90 ? 25 : 0)
            },
            time: Date.now(),
            cached: false,
            reasons: result.reasons,
            modules: result.modules,
            conf: result.conf
          };
          
          const filtered = scanHistory.filter(h => h.url !== url);
          scanHistory = [scanResult, ...filtered].slice(0, 500);
          chrome.storage.local.set({ scanHistory });

          // Save to cache vc_DOMAIN
          chrome.storage.local.set({
            [cacheKey]: {
              result: scanResult,
              timestamp: Date.now()
            }
          });
        }
      }

      render(result);
      updateStatsBar(scanHistory);
    });
  });
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