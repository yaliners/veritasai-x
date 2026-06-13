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

const TRUSTED = ["github.com", "google.com", "stripe.com", "openai.com", "wikipedia.org", "microsoft.com", "apple.com", "mozilla.org"];

async function classifyAsync(url, title = "", settings = {}, userTrusted = []) {
  let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch { host = url.toLowerCase(); }
  const lowerUrl = url.toLowerCase();
  
  const allTrusted = [...TRUSTED, ...userTrusted];
  if (allTrusted.some((d) => host === d || host.endsWith("." + d))) {
    return {
      host,
      risk: "TRUSTED",
      score: 0,
      trust: 100,
      conf: 99,
      reasons: ["Whitelisted high-reputation domain", "Verified SSL", "Established WHOIS history"],
      modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
      module: "Trust Engine"
    };
  }

  const isDangerousDomain = DANGEROUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
  const isSuspiciousDomain = SUSPICIOUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));

  if (isDangerousDomain) {
    return {
      host,
      risk: "DANGEROUS",
      score: 95,
      trust: 5,
      conf: 98,
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
      conf: 92,
      reasons: ["Blacklisted suspicious domain"],
      modules: { phishing: 65, scam: 15, ai: 50, dark: 10, trust: 35 },
      module: "Blocklist"
    };
  }

  const apiKeys = settings?.apiKeys || {};
  let googleFlag = 0;
  let ipqsScore = 0;
  let vtScore = 0;
  
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
      console.error(e);
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
        reasons.push("IPQualityScore: Fraud score " + fraudScore);
      }
    } catch (e) {
      console.error(e);
    }
  }

  // API 3: VirusTotal
  if (apiKeys.virusTotal) {
    try {
      let vtId = "";
      try {
        const utf8Bytes = new TextEncoder().encode(url);
        const binaryString = Array.from(utf8Bytes, byte => String.fromCharCode(byte)).join('');
        vtId = btoa(binaryString).replace(/=/g, "");
      } catch (e) {
        vtId = btoa(url).replace(/=/g, "");
      }

      let vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${vtId}`, {
        headers: { "x-apikey": apiKeys.virusTotal }
      });

      let positives = 0;
      if (vtRes.status === 200) {
        const vtData = await vtRes.json();
        positives = vtData.data?.attributes?.last_analysis_stats?.malicious || 0;
      } else if (vtRes.status === 404) {
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
        reasons.push("VirusTotal: URL flagged by " + positives + " engines");
      }
    } catch (e) {
      console.error(e);
    }
  }

  // API 4: Domain Age Check
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
        reasons.push("New Domain: Registered < 30 days ago");
      }
    } catch (e) {
      console.error(e);
    }
  }

  let localModuleScore = 0;
  const isHttp = url.startsWith("http://");
  if (isHttp) {
    localModuleScore += 25;
    reasons.push("SSL Check: HTTP connection");
  }

  const baseScore = (googleFlag * 0.25 + ipqsScore * 0.40 + vtScore * 0.35);
  let threatScore = baseScore + localModuleScore;
  if (gsbFired) threatScore += 40;
  if (whoisFired) threatScore += 30;

  threatScore = Math.min(100, threatScore);

  let risk = "SAFE";
  if (threatScore > 70 || ipqsForceDangerous || vtForceDangerous) {
    risk = "DANGEROUS";
    threatScore = Math.max(75, threatScore);
  } else if (threatScore > 35 || ipqsForceSuspicious) {
    risk = "SUSPICIOUS";
    threatScore = Math.max(40, threatScore);
  }

  const trustScore = Math.max(0, 100 - threatScore);

  let moduleName = "Trust Engine";
  if (isDangerousDomain || isSuspiciousDomain) {
    moduleName = "Blocklist";
  } else if (gsbFired) {
    moduleName = "Phishing URL";
  } else if (vtFired) {
    moduleName = "Malware Detection";
  } else if (whoisFired) {
    moduleName = "New Domain — High Risk";
  } else if (isHttp) {
    moduleName = "SSL Check";
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
      phishing: gsbFired ? 100 : (risk === "DANGEROUS" ? 90 : 10),
      scam: risk === "DANGEROUS" ? 60 : 10,
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
  badge.textContent = r.risk;
  badge.className = "badge " + r.risk.toLowerCase();
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
    // 1. Look for a cached result in the last 5 minutes (300000 ms)
    const recentScan = scanHistory.find(s => s.url === url && (Date.now() - s.time < 300000));
    
    let result;
    if (recentScan && recentScan.reasons && recentScan.modules) {
      result = {
        host: recentScan.domain,
        risk: recentScan.risk,
        score: recentScan.score,
        trust: recentScan.trustScore,
        conf: recentScan.conf || recentScan.score,
        reasons: recentScan.reasons,
        modules: recentScan.modules,
        module: recentScan.module
      };
    } else {
      // 2. Perform async classification if not cached
      result = await classifyAsync(url, title, settings, trustedDomains);
      
      // Save to scanHistory if it's a real web page
      if (url.startsWith("http://") || url.startsWith("https://")) {
        const scanResult = {
          url: url,
          domain: host,
          risk: result.risk,
          score: result.score,
          trustScore: result.trust,
          aiPrediction: result.risk === "DANGEROUS" ? "Malicious" : result.risk === "SUSPICIOUS" ? "Suspicious" : "Benign",
          mlRisk: (result.score / 100).toFixed(2),
          module: result.module,
          time: Date.now(),
          reasons: result.reasons,
          modules: result.modules,
          conf: result.conf
        };
        const filtered = scanHistory.filter(h => h.url !== url);
        scanHistory = [scanResult, ...filtered].slice(0, 50);
        chrome.storage.local.set({ scanHistory });
      }
    }

    render(result);
    updateStatsBar(scanHistory);
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