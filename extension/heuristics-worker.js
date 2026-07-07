self.onmessage = (e) => {
  const { bodyText = "", hostname = "", protocol = "", formCount = 0 } = e.data;
  let localScore = 0;
  const reasons = [];

  // M1 - Part of Homoglyphs / brand impersonation that can be processed off-thread
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
    if (hostname.includes(h)) {
      localScore += 35;
      reasons.push(`Brand impersonation detected: ${h}`);
    }
  });

  const hyphens = (hostname.match(/-/g) || []).length;
  if (hyphens > 2) {
    localScore += 15;
    reasons.push(`Suspicious domain: ${hyphens} hyphens`);
  }

  // M3 — Content NLP
  const scamPhrases = [
    "you have won",
    "claim now",
    "verify account",
    "act immediately",
    "limited time offer",
    "congratulations you",
    "your account suspended",
    "click here to claim",
    "free gift",
    "urgent action required",
    "wire transfer",
    "bitcoin payment",
    "gift card required",
    "irs notice",
    "legal action",
  ];
  scamPhrases.forEach((phrase) => {
    if (bodyText.includes(phrase)) {
      localScore += 10;
      reasons.push(`Scam phrase: "${phrase}"`);
    }
  });

  // M5 — Form Analysis on HTTPS vs HTTP
  if (protocol === "http:" && formCount > 0) {
    localScore += 20;
    reasons.push("Unsecured page contains forms requesting data");
  }

  // M7 — Page Fingerprint Fake Logins
  const fakeLoginIndicators = ["signin", "login", "account", "secure", "verify"];
  if (formCount > 0 && protocol === "http:") {
    const isFakeLogin = fakeLoginIndicators.some((ind) => bodyText.includes(ind));
    if (isFakeLogin) {
      localScore += 25;
      reasons.push("Fake login page pattern detected");
    }
  }

  self.postMessage({ localScore, reasons });
};
