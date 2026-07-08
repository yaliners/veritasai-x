const handleReportFalsePositive = async (domain) => {
  try {
    const data = await chrome.storage.local.get([
      "falsePositiveList",
      "personalSafeList",
      "scanHistory",
    ]);
    const falsePositiveList = data.falsePositiveList || [];
    const personalSafeList = data.personalSafeList || [];

    if (!falsePositiveList.includes(domain)) {
      falsePositiveList.push(domain);
    }
    if (!personalSafeList.includes(domain)) {
      personalSafeList.push(domain);
    }

    const scanHistory = data.scanHistory || [];
    const updatedHistory = scanHistory.map((h) => {
      if (h.domain === domain) {
        return { ...h, falsePositive: true, confirmed: false, risk: "SAFE", score: 0 };
      }
      return h;
    });

    await chrome.storage.local.set({
      falsePositiveList,
      personalSafeList,
      scanHistory: updatedHistory,
    });

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

    chrome.runtime
      .sendMessage({
        action: "updateBadge",
        risk: "OK",
      })
      .catch(() => {});
  } catch (e) {
    console.warn("Report false positive error:", e.message);
  }
};

export const showOverlay = (result) => {
  if (document.getElementById("veritas-overlay")) return;
  const el = document.createElement("div");
  el.id = "veritas-overlay";

  const reasons = result.reasons || [];
  const evidenceListHtml = reasons
    .map((r) => {
      const cleanText = r.replace(/^[✓\s*-]+/, "");
      return `<li style="margin-bottom:6px;display:flex;align-items:flex-start;gap:8px;color:#e6edf7;">
             <span style="color:#ef4444;font-weight:bold;">⚠</span>
             <span style="text-align:left;">${cleanText}</span>
            </li>`;
    })
    .join("");

  const isLocalOnly = reasons.some((r) => r.includes("Local scan only"));

  const panelHtml = `
    <div style="background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.25);border-radius:10px;padding:14px;margin-bottom:20px;text-align:left;">
      <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(239,68,68,0.15);padding-bottom:8px;margin-bottom:8px;">
        <span style="font-size:12px;font-weight:700;color:#ef4444;text-transform:uppercase;letter-spacing:0.05em;">Evidence</span>
        <div style="display:flex;gap:4px;align-items:center;">
          ${isLocalOnly ? '<span style="font-size:10px;font-weight:700;color:#f59e0b;background:rgba(245,158,11,0.12);padding:2px 8px;border-radius:4px;border:1px solid rgba(245,158,11,0.3);margin-right:6px;">Local scan only</span>' : ""}
          <span style="font-size:12px;font-weight:700;color:#ef4444;background:rgba(239,68,68,0.12);padding:2px 8px;border-radius:4px;">Threat Score: ${result.score}</span>
        </div>
      </div>
      <ul style="list-style:none;padding:0;margin:0;font-size:12px;line-height:1.5;text-align:left;">
        ${evidenceListHtml}
      </ul>
    </div>`;

  el.innerHTML = `
    <div style="position:fixed;inset:0;background:rgba(2,8,23,0.85);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;">
      <div style="max-width:480px;width:100%;background:#081225;border:1px solid rgba(239,68,68,0.5);border-radius:16px;padding:24px;color:#e6edf7;box-shadow:0 20px 60px rgba(0,0,0,0.6);text-align:center;">
        <p style="font-size:11px;letter-spacing:0.2em;color:#ef4444;font-weight:700;margin-bottom:4px;">VERITAS SHIELD ALERT</p>
        <h2 style="font-size:22px;margin:0 0 12px 0;">&#9888; Threat Detected</h2>
        ${panelHtml}
        <div style="display:flex;gap:8px;margin-bottom:12px;">
          <button id="vleave" style="flex:1;padding:10px;border:none;border-radius:10px;background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;font-weight:700;cursor:pointer;">Leave Site</button>
          <button id="vcont" style="flex:1;padding:10px;border:1px solid rgba(154,168,194,0.4);border-radius:10px;background:transparent;color:#9aa8c2;font-weight:600;cursor:pointer;">Continue Anyway</button>
        </div>
        <button id="vfp" style="width:100%;padding:8px;border:none;background:transparent;color:#0ea5e9;font-size:12px;cursor:pointer;text-decoration:underline;">Report false positive →</button>
      </div>
    </div>`;

  document.documentElement.appendChild(el);
  el.querySelector("#vleave").onclick = () => {
    history.back();
  };
  el.querySelector("#vcont").onclick = () => {
    el.remove();
  };
  el.querySelector("#vfp").onclick = () => {
    handleReportFalsePositive(result.domain);
    el.remove();
  };
};

export const showToast = (result, type = "caution") => {
  const existing = document.getElementById("veritas-toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.id = "veritas-toast";

  const accentColor = type === "warning" ? "#ef4444" : "#f59e0b";
  const badgeText = type === "warning" ? "DANGEROUS" : "SUSPICIOUS";
  const primaryReason = result.reasons?.[0] || "Suspicious traffic heuristics matched.";

  toast.setAttribute(
    "style",
    `
    position: fixed;
    bottom: 24px;
    right: 24px;
    width: 320px;
    background: #081225;
    border: 1px solid ${accentColor};
    border-radius: 12px;
    padding: 16px;
    color: #e6edf7;
    font-family: system-ui, sans-serif;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    z-index: 2147483647;
    animation: vtSlideIn 0.3s ease;
  `,
  );

  // Add css animation stylesheet if not exists
  if (!document.getElementById("veritas-toast-styles")) {
    const style = document.createElement("style");
    style.id = "veritas-toast-styles";
    style.textContent = `
      @keyframes vtSlideIn {
        from { transform: translateY(100px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);
  }

  toast.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <span style="font-size:10px;font-weight:800;background:${accentColor}1c;color:${accentColor};padding:2px 6px;border-radius:4px;border:1px solid ${accentColor}40;">
        ${badgeText} (${result.score})
      </span>
      <button id="vtclose" style="background:transparent;border:none;color:#9aa8c2;cursor:pointer;font-size:14px;line-height:1;">✕</button>
    </div>
    <div style="font-size:13px;font-weight:600;margin-bottom:4px;word-break:break-all;">${result.domain}</div>
    <div style="font-size:11px;color:#9aa8c2;margin-bottom:12px;line-height:1.4;">${primaryReason}</div>
    <div style="display:flex;gap:6px;justify-content:flex-end;">
      <button id="vtReportFP" style="padding:6px 10px;border:none;background:transparent;color:#0ea5e9;font-size:11px;cursor:pointer;">Report false positive →</button>
      <button id="vtDismiss" style="padding:6px 10px;border:1px solid rgba(154,168,194,0.3);border-radius:6px;background:transparent;color:#9aa8c2;font-size:11px;cursor:pointer;">Dismiss</button>
    </div>
  `;

  document.documentElement.appendChild(toast);

  const dismiss = () => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  };

  toast.querySelector("#vtclose").onclick = dismiss;
  toast.querySelector("#vtDismiss").onclick = dismiss;
  toast.querySelector("#vtReportFP").onclick = () => {
    handleReportFalsePositive(result.domain);
    dismiss();
  };

  // Auto dismiss after 5 seconds
  const autoTimeout = setTimeout(dismiss, 5000);
  toast.onmouseenter = () => clearTimeout(autoTimeout);
};

export const showAlert = (result, settings) => {
  const alertStyle = settings?.controls?.alertStyle || "Full overlay";
  if (alertStyle === "Badge only") return;

  if (alertStyle === "Full overlay") {
    if (result.risk === "DANGEROUS") {
      showOverlay(result);
    } else if (result.risk === "SUSPICIOUS") {
      showToast(result, "caution");
    }
  } else if (alertStyle === "Toast only") {
    if (result.risk === "DANGEROUS") {
      showToast(result, "warning");
    } else if (result.risk === "SUSPICIOUS") {
      showToast(result, "caution");
    }
  }
};
