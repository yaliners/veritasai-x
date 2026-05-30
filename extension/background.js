chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ history: [], settings: { autoScan: true, overlay: true } });
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url && tab.url.startsWith("http")) {
    chrome.action.setBadgeBackgroundColor({ color: "#00d8ff" });
    chrome.action.setBadgeText({ tabId, text: "AI" });
  }
});