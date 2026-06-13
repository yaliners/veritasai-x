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

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ history: [], settings: { autoScan: true, overlay: true } });
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url && tab.url.startsWith("http")) {
    let host = "";
    try {
      host = new URL(tab.url).hostname.toLowerCase();
    } catch (e) {}

    const isDangerous = DANGEROUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));
    const isSuspicious = SUSPICIOUS_BLOCKLIST.some(d => host === d || host.endsWith("." + d));

    if (isDangerous) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
      chrome.action.setBadgeText({ tabId, text: "DNG" });
    } else if (isSuspicious) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
      chrome.action.setBadgeText({ tabId, text: "SPC" });
    } else {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#00d8ff" });
      chrome.action.setBadgeText({ tabId, text: "AI" });
    }
  }
});