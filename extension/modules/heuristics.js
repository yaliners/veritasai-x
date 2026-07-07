export const runLocalModules = async (settings) => {
  let localScore = 0;
  const reasons = [];

  try {
    const host = window.location.hostname.toLowerCase();
    const protocol = window.location.protocol;
    const bodyText = document.body?.innerText?.toLowerCase() || "";
    const formCount = document.querySelectorAll("input[type='password'], form").length;

    // Run Web Worker for heavy tasks (NLP, homoglyphs, card fields in HTTP)
    const workerPromise = new Promise((resolve) => {
      const worker = new Worker(chrome.runtime.getURL("heuristics-worker.js"));
      worker.postMessage({ bodyText, hostname: host, protocol, formCount });
      worker.onmessage = (e) => {
        resolve(e.data);
        worker.terminate();
      };
      // Timeout after 2 seconds to avoid hangs
      setTimeout(() => {
        resolve({ localScore: 0, reasons: [] });
        worker.terminate();
      }, 2000);
    });

    const workerResult = await workerPromise;
    localScore += workerResult.localScore;
    reasons.push(...workerResult.reasons);

    // M1 - Basic IP domain check
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      localScore += 30;
      reasons.push("IP address used instead of domain name");
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

    // M2 — SSL Check
    if (protocol === "http:") {
      localScore += 25;
      reasons.push("No HTTPS encryption");
    }

    // M4 — Dark Pattern Detection
    const checkedBoxes = document.querySelectorAll("input[type='checkbox']:checked");
    if (checkedBoxes.length > 0) {
      localScore += 10;
      reasons.push("Pre-checked consent boxes found");
    }

    // countdowns
    const countdowns = document.querySelectorAll(
      "[class*='countdown'],[class*='timer'],[id*='countdown'],[id*='timer']",
    );
    if (countdowns.length > 0) {
      localScore += 15;
      reasons.push("Fake urgency timer detected");
    }

    // M6 — Redirect Chain
    if (performance.navigation?.redirectCount > 3) {
      localScore += 15;
      reasons.push("Excessive redirects: " + performance.navigation.redirectCount);
    }

    // M8 — Clickjacking / Sandboxed Iframe Check
    const iframes = document.querySelectorAll("iframe");
    if (iframes.length > 2) {
      localScore += 10;
      reasons.push("Excessive iframe elements detected (" + iframes.length + ")");
    }

    // M9 — Voice Clone Monitoring (Beta check)
    if (settings?.modules?.voiceClone) {
      const audioElements = document.querySelectorAll("audio, video");
      let hasSyntheticPattern = false;
      audioElements.forEach((el) => {
        if (
          el.src &&
          (el.src.includes("synth") ||
            el.src.includes("ai-voice") ||
            el.src.includes("clone") ||
            el.src.includes("speech"))
        ) {
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
    }

    // QR Code Check
    if (settings?.modules?.qrDetector) {
      const qrImages = document.querySelectorAll("img[src*='qr'], img[alt*='qr'], canvas");
      if (qrImages.length > 0) {
        localScore += 10;
        reasons.push("QR code element found on page (potential Quishing)");
      }
    }

    // M10 — Fake Review Detection
    const reviews = document.querySelectorAll(".review, [class*='review'], [id*='review']");
    let suspiciousReviewPatterns = false;
    reviews.forEach((el) => {
      const text = el.innerText?.toLowerCase() || "";
      if (
        ["delve", "testament", "moreover", "highly recommend", "game changer"].filter((w) =>
          text.includes(w),
        ).length > 2
      ) {
        suspiciousReviewPatterns = true;
      }
    });
    if (suspiciousReviewPatterns) {
      localScore += 10;
      reasons.push("Repetitive / AI-generated review patterns detected");
    }

    // M11 — Fake Support Chat widget Detection
    const chatWidgets = document.querySelectorAll(
      "[class*='chat'],[id*='chat'],[class*='support'],[id*='support']",
    );
    let isScamChat = false;
    chatWidgets.forEach((el) => {
      const text = el.innerText?.toLowerCase() || "";
      if (
        text.includes("help desk") ||
        text.includes("support desk") ||
        text.includes("agent live") ||
        text.includes("customer service")
      ) {
        if (protocol === "http:") {
          isScamChat = true;
        }
      }
    });
    if (isScamChat) {
      localScore += 20;
      reasons.push("Unsecured customer support widget (scam chat risk)");
    }

    // M13 — Hidden Script Analysis
    const scripts = document.querySelectorAll("script");
    let hasMinerOrObfuscation = false;
    scripts.forEach((s) => {
      const src = s.src?.toLowerCase() || "";
      const content = s.textContent || "";
      if (src.includes("coinhive") || src.includes("cryptonight") || src.includes("miner.js")) {
        hasMinerOrObfuscation = true;
      }
      if (
        content.includes("eval(function(p,a,c,k,e,d)") ||
        content.includes("\\x65\\x76\\x61\\x6c")
      ) {
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

  return { localScore, reasons };
};
