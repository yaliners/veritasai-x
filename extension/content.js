(function () {
  if (window.location.href.includes("veritasai-x.vercel.app")) {
    chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
      localStorage.setItem("veritasai_scans", JSON.stringify(scanHistory));
      window.dispatchEvent(new StorageEvent("storage", { key: "veritasai_scans", newValue: JSON.stringify(scanHistory) }));
    });
    return;
  }

  const url = location.href;
  const PHISHING = ["login", "verify", "bank", "password", "otp", "suspended"];
  const SCAM = ["giveaway", "claim reward", "send bitcoin", "wire transfer", "gift card"];
  const text = document.body ? document.body.innerText.toLowerCase() : "";
  let score = 0;
  const reasons = [];
  PHISHING.forEach((k) => { if (url.toLowerCase().includes(k)) { score += 20; reasons.push("Phishing keyword: " + k); } });
  SCAM.forEach((k) => { if (text.includes(k)) { score += 25; reasons.push("Scam phrase: " + k); } });
  if (document.querySelector('input[type="password"]') && !location.protocol.includes("https")) { score += 30; reasons.push("Password field on insecure page"); }

  const scanResult = {
    url: url,
    domain: new URL(url).hostname,
    risk: score >= 85 ? "DANGEROUS" : score >= 50 ? "SUSPICIOUS" : "SAFE",
    score: Math.min(100, score),
    trustScore: Math.max(0, 100 - score),
    aiPrediction: score >= 85 ? "Malicious" : score >= 50 ? "Suspicious" : "Benign",
    mlRisk: (Math.min(100, score) / 100).toFixed(2),
    time: Date.now(),
  };

  chrome.storage.local.get(["scanHistory"], ({ scanHistory = [] }) => {
    const updated = [scanResult, ...scanHistory].slice(0, 50);
    chrome.storage.local.set({ scanHistory: updated });
    localStorage.setItem("veritasai_scans", JSON.stringify(updated));
  });

  if (score >= 65) {
    chrome.storage.local.get(["settings"], ({ settings = { overlay: true } }) => {
      if (!settings.overlay) return;
      showOverlay(score, reasons);
    });
  }

  function showOverlay(score, reasons) {
    if (document.getElementById("veritas-overlay")) return;
    const el = document.createElement("div");
    el.id = "veritas-overlay";
    el.innerHTML = '<div style="position:fixed;inset:0;background:rgba(2,8,23,0.85);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;"><div style="max-width:480px;background:#081225;border:1px solid rgba(239,68,68,0.5);border-radius:16px;padding:24px;color:#e6edf7;box-shadow:0 20px 60px rgba(0,0,0,0.6);"><p style="font-size:11px;letter-spacing:0.2em;color:#ef4444;font-weight:700;">VERITASAI X ALERT</p><h2 style="font-size:22px;margin:6px 0 4px;">&#9888; Threat Detected</h2><p style="font-size:13px;color:#9aa8c2;margin-bottom:16px;">This page exhibits malicious patterns. Risk Score: <b style="color:#ef4444">' + score + '</b></p><ul style="margin:0 0 18px 16px;font-size:12px;line-height:1.7;">' + reasons.map(function(r){return "<li>"+r+"</li>";}).join("") + '</ul><div style="display:flex;gap:8px;"><button id="vleave" style="flex:1;padding:10px;border:none;border-radius:10px;background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;font-weight:700;cursor:pointer;">Leave Site</button><button id="vcont" style="flex:1;padding:10px;border:1px solid rgba(154,168,194,0.4);border-radius:10px;background:transparent;color:#9aa8c2;font-weight:600;cursor:pointer;">Continue Anyway</button></div></div></div>';
    document.documentElement.appendChild(el);
    el.querySelector("#vleave").onclick = function() { history.back(); };
    el.querySelector("#vcont").onclick = function() { el.remove(); };
  }
})();