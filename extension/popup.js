let currentSite = "";
let currentUrl = "";

const PERMANENT_SAFE = [
  "google.com",
  "youtube.com",
  "github.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "claude.ai",
  "chatgpt.com",
  "linkedin.com",
  "twitter.com",
  "instagram.com",
  "facebook.com",
  "whatsapp.com",
  "wikipedia.org",
  "stackoverflow.com",
  "netflix.com",
  "spotify.com",
  "reddit.com",
  "anthropic.com",
  "openai.com",
  "veritasai-shield.vercel.app",
];

const getBaseDomain = (hostname) => {
  return hostname.replace(/^www\./, "").toLowerCase();
};

const withTimeout = (promise, ms) => {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
  ]);
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
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".click",
    ".top",
    ".gq",
    ".pw",
    ".work",
    ".loan",
    ".date",
    ".racing",
    ".win",
    ".download",
    ".stream",
    ".party",
    ".review",
  ];
  suspTLDs.forEach((tld) => {
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
    "paypa1",
    "amaz0n",
    "g00gle",
    "app1e",
    "faceb00k",
    "netfl1x",
    "lnstagram",
    "tw1tter",
    "micros0ft",
    "paypai",
  ];
  homoglyphs.forEach((h) => {
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
    reasons,
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

  // Call secure serverless proxy
  let proxyVerdict = null;
  try {
    const res = await withTimeout(
      fetch("https://veritasai-shield.vercel.app/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, domain: baseDomain }),
      }),
      5000,
    );
    if (res.ok) {
      proxyVerdict = await res.json();
    }
  } catch (e) {
    console.warn("Proxy failed inside popup:", e.message);
  }

  // Cloudflare DNS local fallback
  let dnsFlag = 0;
  let dnsReason = null;
  try {
    const res = await withTimeout(
      fetch(
        "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(baseDomain) + "&type=A",
        { headers: { Accept: "application/dns-json" } },
      ),
      3000,
    );
    if (res.ok) {
      const data = await res.json();
      if (data.Status !== 0 || !data.Answer?.length) {
        dnsFlag = 20;
        dnsReason = "DNS anomaly detected — domain may not resolve properly";
      }
    }
  } catch (e) {}

  // Local modules local fallback
  const { localScore, reasons: localReasons } = runLocalModules(url, baseDomain);

  let google = { score: 0, matched: false, reason: null };
  let urlscan = { score: 0, reason: null };
  let vt = { score: 0, reason: null, malicious: 0, total: 0 };
  let rdap = { flag: 0, ageDays: null, reason: null };
  let abuse = { score: 0, reason: null };

  if (proxyVerdict) {
    google = proxyVerdict.google || google;
    urlscan = proxyVerdict.urlscan || urlscan;
    vt = proxyVerdict.virustotal || vt;
    abuse = proxyVerdict.abuse || abuse;
    rdap = proxyVerdict.rdap || rdap;
  }

  const googleFlag = google.matched ? 100 : 0;
  const urlscanScore = urlscan.score || 0;
  const vtScore = vt.score || 0;
  const whoisFlag = rdap.flag || 0;
  const abuseScore = abuse.score || 0;

  const apiScore = Math.round(
    googleFlag * 0.25 + urlscanScore * 0.25 + vtScore * 0.25 + abuseScore * 0.15 + dnsFlag * 0.1,
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
  } else if (urlscan.forceSUSPICIOUS || abuse.forceSUSPICIOUS || threatScore > 35) {
    risk = "SUSPICIOUS";
  }

  const allReasons = [
    google.reason,
    urlscan.reason,
    vt.reason,
    rdap.reason,
    abuse.reason,
    dnsReason,
    ...localReasons,
  ].filter(Boolean);

  if (!proxyVerdict) {
    allReasons.push("Local scan only — Proxy unavailable");
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
      trust: Math.round(trustScore),
    },
    module: moduleName,
    subScores: {
      google: googleFlag,
      urlscan: urlscanScore,
      virustotal: vtScore,
      domainAge: whoisFlag,
      abuse: abuseScore,
      dns: dnsFlag,
      local: localScore,
    },
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

  const defaultModules = [
    "Phishing URL",
    "Scam Pattern",
    "AI Content",
    "Dark Pattern",
    "Trust Engine",
  ];
  document.getElementById("modules").innerHTML = defaultModules
    .map((m) => {
      return `<li><span>${m}</span><span style="color:#6b7a99;">Checking...</span></li>`;
    })
    .join("");

  document.getElementById("reasons").innerHTML =
    `<li>Scanning page for security vulnerabilities...</li>`;
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
  document.getElementById("modules").innerHTML = mods
    .map((m) => {
      const cls =
        m.name === "Trust Engine"
          ? m.v > 70
            ? "ok"
            : m.v > 40
              ? "warn"
              : "bad"
          : m.v > 60
            ? "bad"
            : m.v > 30
              ? "warn"
              : "ok";
      return `<li><span>${m.name}</span><span class="${cls}">${m.v}</span></li>`;
    })
    .join("");

  const hasLocalOnly = (r.reasons || []).some((x) => x.includes("Local scan only"));

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
      })
      .join("");

    document.getElementById("reasons").innerHTML = `
      <div style="background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 12px; margin-top: 4px; text-align: left; width: 100%;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(239, 68, 68, 0.15); padding-bottom: 8px; margin-bottom: 8px;">
          <span style="font-size: 11px; font-weight: 700; color: #ef4444; text-transform: uppercase; letter-spacing: 0.05em;">Evidence</span>
          <div style="display: flex; gap: 4px; align-items: center;">
            ${hasLocalOnly ? `<span style="font-size: 9px; font-weight: 700; color: #f59e0b; background: rgba(245, 158, 11, 0.12); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.3);">Local scan only</span>` : ""}
            <span style="font-size: 11px; font-weight: 700; color: #ef4444; background: rgba(239, 68, 68, 0.12); padding: 2px 6px; border-radius: 4px;">Threat Score: ${r.score || 0}</span>
          </div>
        </div>
        <ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px;">
          ${evidenceListHtml}
        </ul>
      </div>
    `;
  } else {
    let reasonsHtml = (r.reasons || [])
      .slice(0, 5)
      .map((x) => `<li>${x}</li>`)
      .join("");
    if (hasLocalOnly) {
      reasonsHtml = `
        <div style="background: rgba(245, 158, 11, 0.05); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 8px; padding: 12px; margin-top: 4px; text-align: left; width: 100%;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(245, 158, 11, 0.15); padding-bottom: 8px; margin-bottom: 8px;">
            <span style="font-size: 11px; font-weight: 700; color: #f59e0b; text-transform: uppercase; letter-spacing: 0.05em;">AI Explanation</span>
            <span style="font-size: 9px; font-weight: 700; color: #f59e0b; background: rgba(245, 158, 11, 0.12); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.3);">Local scan only</span>
          </div>
          <ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px; font-size: 11px;">
            ${(r.reasons || [])
              .filter((x) => !x.includes("Local scan only"))
              .map((x) => `<li>${x}</li>`)
              .join("")}
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
  document.getElementById("reasons").innerHTML =
    `<li>Click 'Scan Now' to run real-time threat intelligence scan.</li>`;
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
      aiPrediction:
        result.risk === "DANGEROUS"
          ? "Threat detected — do not proceed"
          : result.risk === "SUSPICIOUS"
            ? "Suspicious activity detected"
            : "No threats detected",
      mlRisk: result.score > 70 ? "High" : result.score > 35 ? "Medium" : "Low",
      subScores: result.subScores || {
        google: 0,
        urlscan: 0,
        virustotal: 0,
        domainAge: 0,
        abuse: 0,
        dns: 0,
        local: 0,
      },
      time: Date.now(),
      cached: false,
      reasons: result.reasons,
      modules: modules,
      conf: result.conf,
    };

    const filtered = scanHistory.filter((h) => h.url !== url);
    const updatedHistory = [scanResult, ...filtered].slice(0, 500);
    chrome.storage.local.set({ scanHistory: updatedHistory });

    chrome.storage.local.set({
      [cacheKey]: {
        result: scanResult,
        timestamp: Date.now(),
      },
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
    (safe) => baseDomain === safe || baseDomain.endsWith("." + safe),
  );

  chrome.storage.local.get(
    ["scanHistory", "settings", "trustedDomains"],
    async ({ scanHistory = [], settings = {}, trustedDomains = [] }) => {
      const controls = settings?.controls || {
        autoScan: true,
        popupAlerts: true,
        overlayAlerts: true,
      };
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
          module: "Trust Engine",
        };
        render(result);
        saveAndRender(result, cacheKey, host, url, scanHistory);
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" }).catch(() => {});
        return;
      }

      chrome.storage.local.get([cacheKey], async (cachedData) => {
        const cacheEntry = cachedData[cacheKey];
        let result;

        if (cacheEntry && cacheEntry.timestamp && Date.now() - cacheEntry.timestamp < 3600000) {
          const cachedResult = cacheEntry.result;
          result = {
            host: cachedResult.domain,
            risk: cachedResult.risk,
            score: cachedResult.score,
            trust: cachedResult.trustScore,
            conf: cachedResult.conf || cachedResult.score,
            reasons: cachedResult.reasons,
            modules: cachedResult.modules,
            module: cachedResult.module,
          };
          render(result, true);
          updateStatsBar(scanHistory);
        } else {
          renderLoading(host);
          chrome.runtime.sendMessage({ action: "updateBadge", risk: "SCANNING" }).catch(() => {});

          if (!controls.autoScan) {
            renderPlaceholder(host);
            updateStatsBar(scanHistory);
          } else {
            result = await classifyAsync(url, title);
            saveAndRender(result, cacheKey, host, url, scanHistory);
            chrome.runtime
              .sendMessage({ action: "updateBadge", risk: result.risk })
              .catch(() => {});
          }
        }
      });
    },
  );
});

document.getElementById("scanNow").addEventListener("click", async () => {
  const btn = document.getElementById("scanNow");
  btn.textContent = "Scanning...";
  btn.disabled = true;

  try {
    renderLoading(currentSite);
    chrome.runtime.sendMessage({ action: "updateBadge", risk: "SCANNING" }).catch(() => {});
    const result = await classifyAsync(currentUrl, "");
    const cacheKey = "vc_" + currentSite.replace(/^www\./, "").toLowerCase();
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      saveAndRender(result, cacheKey, currentSite, currentUrl, scanHistory);
      chrome.runtime.sendMessage({ action: "updateBadge", risk: result.risk }).catch(() => {});
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
  const blocked = history.filter((x) => x.risk === "DANGEROUS").length;
  const safe = history.filter((x) => x.risk === "SAFE").length;

  document.getElementById("totalScanned").textContent = total;
  document.getElementById("threatsBlocked").textContent = blocked;
  document.getElementById("safeSites").textContent = safe;
}

document.getElementById("openDash").addEventListener("click", () => {
  chrome.tabs.create({ url: "https://veritasai-shield.vercel.app/dashboard" });
});

document.getElementById("reportDangerous").addEventListener("click", () => {
  chrome.storage.local.get(
    ["personalBlocklist", "scanHistory"],
    ({ personalBlocklist = [], scanHistory = [] }) => {
      if (!personalBlocklist.includes(currentSite)) {
        personalBlocklist.push(currentSite);
      }
      chrome.storage.local.set({ personalBlocklist }, () => {
        const scanResult = {
          host: currentSite,
          risk: "DANGEROUS",
          score: 100,
          trust: 0,
          conf: 100,
          reasons: ["User reported dangerous domain"],
          modules: { phishing: 100, scam: 100, ai: 0, dark: 0, trust: 0 },
          module: "User Reported",
        };
        render(scanResult);

        if (currentUrl.startsWith("http://") || currentUrl.startsWith("https://")) {
          const cacheKey = "vc_" + currentSite.replace(/^www\./, "").toLowerCase();
          const historyScanResult = {
            url: currentUrl,
            domain: currentSite,
            risk: "DANGEROUS",
            score: 100,
            trustScore: 0,
            mlConfidence: "100%",
            module: "User Reported",
            aiPrediction: "Threat detected — user block override",
            mlRisk: "High",
            subScores: {
              google: 0,
              urlscan: 0,
              virustotal: 0,
              domainAge: 0,
              abuse: 0,
              dns: 0,
              local: 0,
            },
            time: Date.now(),
            cached: false,
            reasons: ["User reported dangerous domain"],
            modules: { phishing: 100, scam: 100, ai: 0, dark: 0, trust: 0 },
            conf: 100,
          };
          const filtered = scanHistory.filter((h) => h.url !== currentUrl);
          const updatedHistory = [historyScanResult, ...filtered].slice(0, 500);
          chrome.storage.local.set({ scanHistory: updatedHistory });
          chrome.storage.local.set({
            [cacheKey]: {
              result: historyScanResult,
              timestamp: Date.now(),
            },
          });
          updateStatsBar(updatedHistory);
        }

        const btn = document.getElementById("reportDangerous");
        btn.textContent = "Marked as dangerous ✓";
        setTimeout(() => {
          btn.textContent = "🚨 Report Dangerous";
        }, 2000);

        chrome.runtime.sendMessage({ action: "updateBadge", risk: "DANGEROUS" }).catch(() => {});
      });
    },
  );
});

document.getElementById("reportSafe").addEventListener("click", () => {
  chrome.storage.local.get(
    ["personalSafeList", "scanHistory"],
    ({ personalSafeList = [], scanHistory = [] }) => {
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
          module: "User Verified",
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
            subScores: {
              google: 0,
              urlscan: 0,
              virustotal: 0,
              domainAge: 0,
              abuse: 0,
              dns: 0,
              local: 0,
            },
            time: Date.now(),
            cached: false,
            reasons: ["User verified safe domain"],
            modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
            conf: 100,
          };
          const filtered = scanHistory.filter((h) => h.url !== currentUrl);
          const updatedHistory = [historyScanResult, ...filtered].slice(0, 500);
          chrome.storage.local.set({ scanHistory: updatedHistory });
          chrome.storage.local.set({
            [cacheKey]: {
              result: historyScanResult,
              timestamp: Date.now(),
            },
          });
          updateStatsBar(updatedHistory);
        }

        const btn = document.getElementById("reportSafe");
        btn.textContent = "Marked as safe ✓";
        setTimeout(() => {
          btn.textContent = "✅ Report Safe";
        }, 2000);

        chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" }).catch(() => {});
      });
    },
  );
});

// User Accuracy Feedback Hooks (IMPROVEMENT 10)
document.getElementById("feedbackYes").addEventListener("click", () => {
  chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
    const updatedHistory = scanHistory.map((h) => {
      if (h.domain === currentSite) {
        return { ...h, confirmed: true, falsePositive: false };
      }
      return h;
    });
    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
      const isVeritasSite =
        window.location.href.includes("veritasai-shield.vercel.app") ||
        window.location.href.includes("localhost:") ||
        window.location.href.includes("127.0.0.1:");
      if (isVeritasSite) {
        localStorage.setItem("veritasai_scans", JSON.stringify(updatedHistory));
        window.dispatchEvent(
          new StorageEvent("storage", {
            key: "veritasai_scans",
            newValue: JSON.stringify(updatedHistory),
          }),
        );
      }
      const resp = document.getElementById("feedbackResponse");
      resp.textContent = "Thank you for confirming";
      resp.style.display = "block";
    });
  });
});

document.getElementById("feedbackNo").addEventListener("click", () => {
  chrome.storage.local.get(
    ["personalSafeList", "scanHistory"],
    ({ personalSafeList = [], scanHistory = [] }) => {
      if (!personalSafeList.includes(currentSite)) {
        personalSafeList.push(currentSite);
      }
      const updatedHistory = scanHistory.map((h) => {
        if (h.domain === currentSite) {
          return { ...h, falsePositive: true, confirmed: false, risk: "SAFE", score: 0 };
        }
        return h;
      });

      chrome.storage.local.set({ personalSafeList, scanHistory: updatedHistory }, () => {
        chrome.runtime.sendMessage({ action: "updateBadge", risk: "SAFE" }).catch(() => {});

        const isVeritasSite =
          window.location.href.includes("veritasai-shield.vercel.app") ||
          window.location.href.includes("localhost:") ||
          window.location.href.includes("127.0.0.1:");
        if (isVeritasSite) {
          localStorage.setItem("veritasai_scans", JSON.stringify(updatedHistory));
          window.dispatchEvent(
            new StorageEvent("storage", {
              key: "veritasai_scans",
              newValue: JSON.stringify(updatedHistory),
            }),
          );
        }

        const safeScanResult = {
          host: currentSite,
          risk: "SAFE",
          score: 0,
          trust: 100,
          conf: 100,
          reasons: ["User marked false positive - added to Safe List"],
          modules: { phishing: 0, scam: 0, ai: 0, dark: 0, trust: 100 },
          module: "User Override",
        };
        render(safeScanResult);

        const resp = document.getElementById("feedbackResponse");
        resp.textContent = "Added to safe list";
        resp.style.display = "block";
      });
    },
  );
});
