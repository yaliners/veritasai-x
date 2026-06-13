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

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ scanHistory: [], settings: { autoScan: true, overlayAlerts: true } });
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url && tab.url.startsWith("http")) {
    let host = "";
    try {
      host = new URL(tab.url).hostname.toLowerCase();
    } catch (e) {}

    const isDangerous = DANGEROUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
    const isSuspicious = SUSPICIOUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
    const isSafe = PERMANENT_SAFE.some(d => host === d || host.endsWith("." + d));

    if (isSafe) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#06B6D4" });
      chrome.action.setBadgeText({ tabId, text: "✓" });
    } else if (isDangerous) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
      chrome.action.setBadgeText({ tabId, text: "DNG" });
    } else if (isSuspicious) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
      chrome.action.setBadgeText({ tabId, text: "SPC" });
    } else {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#22C55E" });
      chrome.action.setBadgeText({ tabId, text: "OK" });
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.action === "updateBadge" && sender.tab) {
    const tabId = sender.tab.id;
    if (message.risk === "DANGEROUS") {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
      chrome.action.setBadgeText({ tabId, text: "DNG" });
    } else if (message.risk === "SUSPICIOUS") {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
      chrome.action.setBadgeText({ tabId, text: "SPC" });
    } else if (message.risk === "TRUSTED") {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#06B6D4" });
      chrome.action.setBadgeText({ tabId, text: "✓" });
    } else {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#22C55E" });
      chrome.action.setBadgeText({ tabId, text: "OK" });
    }
  }
});