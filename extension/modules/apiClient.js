const withTimeout = (promise, ms) => {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
  ]);
};

export const getVerdict = async (url, domain) => {
  try {
    const res = await withTimeout(
      fetch("https://veritasai-shield.vercel.app/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, domain }),
      }),
      5000,
    );
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.warn("Proxy failed, falling back:", e.message);
    return null;
  }
};

export const checkCloudfareDNS = async (domain) => {
  try {
    const res = await withTimeout(
      fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(domain) + "&type=A", {
        headers: { Accept: "application/dns-json" },
      }),
      3000,
    );

    if (!res.ok) return { flag: 0, reason: null, error: true };
    const data = await res.json();
    const status = data.Status;
    const hasAnswers = data.Answer?.length > 0;

    if (status !== 0 || !hasAnswers) {
      return {
        flag: 20,
        reason: "DNS anomaly detected — domain may not resolve properly",
      };
    }

    return { flag: 0, reason: null };
  } catch (e) {
    console.warn("DNS check failed:", e.message);
    return { flag: 0, reason: null, error: true };
  }
};
