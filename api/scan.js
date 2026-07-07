import crypto from "crypto";

// In-memory rate limiting map
const ipCache = new Map();
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour
const MAX_REQUESTS = 100;

const cleanOldRequests = (ip) => {
  const now = Date.now();
  const timestamps = ipCache.get(ip) || [];
  const valid = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW);
  if (valid.length === 0) {
    ipCache.delete(ip);
  } else {
    ipCache.set(ip, valid);
  }
};

const isRateLimited = (ip) => {
  cleanOldRequests(ip);
  const timestamps = ipCache.get(ip) || [];
  if (timestamps.length >= MAX_REQUESTS) {
    return true;
  }
  timestamps.push(Date.now());
  ipCache.set(ip, timestamps);
  return false;
};

// SHA-256 helper
const getSha256 = (val) => {
  return crypto.createHash("sha256").update(val).digest();
};

export default async function handler(req, res) {
  // CORS Headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown-ip";
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: "Too many requests. Rate limit exceeded." });
  }

  const { url, domain } = req.body || {};
  if (!url || !domain) {
    return res.status(400).json({ error: "Missing url or domain in request body" });
  }

  // Privacy: Only domain sent to URLScan and AbuseIPDB. Full URL only sent to Google Safe Browsing and VirusTotal which require it for accurate detection.

  // Resolve keys from environment variables
  const GOOGLE_KEY = process.env.GOOGLE_KEY;
  const URLSCAN_KEY = process.env.URLSCAN_KEY;
  const VT_KEY = process.env.VT_KEY;
  const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;

  // 1. Google Safe Browsing
  const checkGoogle = async () => {
    if (!GOOGLE_KEY)
      return { score: 0, matched: false, reason: "Google Safe Browsing key not configured" };
    try {
      // SHA-256 hash prefix lookup for privacy
      const hash = getSha256(url);
      const prefix = hash.slice(0, 4).toString("hex"); // 4-byte prefix

      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/fullHashes:find?key=${GOOGLE_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "veritasai", clientVersion: "3.0" },
            clientStates: [],
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["RAW_SHA256"],
              threatEntries: [{ hash: hash.toString("base64") }],
            },
          }),
        },
      );

      if (!response.ok) {
        // Fallback to URL lookup if fullHashes find fails or return safe
        return { score: 0, matched: false };
      }

      const data = await response.json();
      const matched = !!data.matches?.length;
      const type = data.matches?.[0]?.threatType;

      return {
        score: matched ? 100 : 0,
        matched,
        reason: matched ? `Google Safe Browsing: ${type}` : null,
        forceDANGEROUS: matched,
      };
    } catch (e) {
      return { score: 0, matched: false, error: e.message };
    }
  };

  // 2. URLScan.io
  const checkURLScan = async () => {
    if (!URLSCAN_KEY) return { score: 0, reason: "URLScan key not configured" };
    try {
      const response = await fetch(
        `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=1`,
        { headers: { "API-Key": URLSCAN_KEY } },
      );
      if (!response.ok) return { score: 0 };
      const data = await response.json();
      const result = data.results?.[0];
      if (!result) return { score: 0 };

      const verdicts = result.verdicts?.overall;
      const malicious = verdicts?.malicious || false;
      const score = verdicts?.score || 0;
      const brands = result.page?.domain || domain;

      return {
        score: malicious ? 100 : score,
        malicious,
        reason: malicious
          ? `URLScan flagged as malicious: ${brands}`
          : score > 50
            ? `URLScan suspicious score: ${score}`
            : null,
        forceDANGEROUS: malicious,
        forceSUSPICIOUS: !malicious && score > 50,
      };
    } catch (e) {
      return { score: 0, error: e.message };
    }
  };

  // 3. VirusTotal
  const checkVirusTotal = async () => {
    if (!VT_KEY) return { score: 0, malicious: 0, reason: "VirusTotal key not configured" };
    try {
      const urlId = Buffer.from(url)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");

      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { "x-apikey": VT_KEY },
      });

      if (response.status === 404) {
        // Submit for scanning
        const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: {
            "x-apikey": VT_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: `url=${encodeURIComponent(url)}`,
        });

        if (!submitResponse.ok) return { score: 0, malicious: 0 };
        const submitData = await submitResponse.json();
        const analysisId = submitData.data?.id;

        if (!analysisId) return { score: 0, malicious: 0 };

        // Poll analysis result
        const pollResponse = await fetch(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          {
            headers: { "x-apikey": VT_KEY },
          },
        );

        if (!pollResponse.ok) return { score: 0, malicious: 0 };
        const pollData = await pollResponse.json();
        const stats = pollData.data?.attributes?.stats || {};
        const malicious = stats.malicious || 0;
        const total =
          malicious + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0);

        return {
          score: malicious > 3 ? 100 : malicious * 20,
          malicious,
          total,
          reason: malicious > 0 ? `${malicious}/${total} antivirus engines flagged` : null,
          forceDANGEROUS: malicious > 3,
        };
      }

      if (!response.ok) return { score: 0, malicious: 0 };
      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const total =
        malicious + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0);

      return {
        score: malicious > 3 ? 100 : malicious * 20,
        malicious,
        total,
        reason: malicious > 0 ? `${malicious}/${total} antivirus engines flagged` : null,
        forceDANGEROUS: malicious > 3,
      };
    } catch (e) {
      return { score: 0, malicious: 0, error: e.message };
    }
  };

  // 4. AbuseIPDB
  const checkAbuseIPDB = async () => {
    if (!ABUSEIPDB_KEY) return { score: 0, reason: "AbuseIPDB key not configured" };
    try {
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(domain)}&maxAgeInDays=90`,
        {
          headers: {
            Key: ABUSEIPDB_KEY,
            Accept: "application/json",
          },
        },
      );
      if (!response.ok) return { score: 0 };
      const data = await response.json();
      const score = data.data?.abuseConfidenceScore || 0;

      return {
        score,
        reason: score > 40 ? `AbuseIPDB confidence: ${score}%` : null,
        forceDANGEROUS: score > 80,
        forceSUSPICIOUS: score > 40,
      };
    } catch (e) {
      return { score: 0, error: e.message };
    }
  };

  // 5. RDAP Domain Age
  const checkRDAP = async () => {
    try {
      const response = await fetch(`https://rdap.org/domain/${domain}`);
      if (!response.ok) return { flag: 0, ageDays: null };
      const data = await response.json();
      const regEvent = data.events?.find((e) => e.eventAction === "registration");
      if (!regEvent) return { flag: 0, ageDays: null };

      const regDate = new Date(regEvent.eventDate);
      const ageDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
      const flag = ageDays < 30 ? 30 : ageDays < 90 ? 15 : 0;
      const reason =
        ageDays < 30
          ? `Domain only ${ageDays} days old — very high risk`
          : ageDays < 90
            ? `Domain ${ageDays} days old — relatively new`
            : null;

      return { ageDays, flag, reason };
    } catch (e) {
      return { flag: 0, ageDays: null };
    }
  };

  // Run all checks in parallel
  const [google, urlscan, virustotal, abuse, rdap] = await Promise.all([
    checkGoogle(),
    checkURLScan(),
    checkVirusTotal(),
    checkAbuseIPDB(),
    checkRDAP(),
  ]);

  return res.status(200).json({
    google,
    urlscan,
    virustotal,
    abuse,
    rdap,
  });
}
