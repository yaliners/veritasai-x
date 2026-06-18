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
  chrome.storage.local.get(null, (items) => {
    const keysToRemove = Object.keys(items).filter(key => key.startsWith("vc_"));
    if (keysToRemove.length > 0) {
      chrome.storage.local.remove(keysToRemove);
    }
  });

  chrome.storage.local.set({
    scanHistory: [],
    settings: {
      modules: { phishing: true, scam: true, aiContent: true, darkPattern: true, qrDetector: false, voiceClone: false },
      controls: { autoScan: true, popupAlerts: true, overlayAlerts: true }
    }
  });
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url && tab.url.startsWith("http")) {
    chrome.storage.local.get(["settings"], ({ settings = {} }) => {
      const controls = settings?.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
      
      if (!controls.popupAlerts) {
        chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
        return;
      }

      let host = "";
      try {
        host = new URL(tab.url).hostname.toLowerCase();
      } catch (e) {}

      chrome.action.setBadgeBackgroundColor({ tabId, color: "#22C55E" }).catch(() => {});
      chrome.action.setBadgeText({ tabId, text: "OK" }).catch(() => {});
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.action === "updateBadge") {
    chrome.storage.local.get(["settings"], ({ settings = {} }) => {
      const controls = settings?.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
      const tabId = sender.tab ? sender.tab.id : null;

      const applyBadge = (tId) => {
        if (!controls.popupAlerts) {
          chrome.action.setBadgeText({ tabId: tId, text: "" }).catch(() => {});
          return;
        }
        if (message.risk === "DANGEROUS") {
          chrome.action.setBadgeBackgroundColor({ tabId: tId, color: "#EF4444" }).catch(() => {});
          chrome.action.setBadgeText({ tabId: tId, text: "DNG" }).catch(() => {});
        } else if (message.risk === "SUSPICIOUS") {
          chrome.action.setBadgeBackgroundColor({ tabId: tId, color: "#F59E0B" }).catch(() => {});
          chrome.action.setBadgeText({ tabId: tId, text: "SPC" }).catch(() => {});
        } else if (message.risk === "TRUSTED") {
          chrome.action.setBadgeBackgroundColor({ tabId: tId, color: "#06B6D4" }).catch(() => {});
          chrome.action.setBadgeText({ tabId: tId, text: "✓" }).catch(() => {});
        } else {
          chrome.action.setBadgeBackgroundColor({ tabId: tId, color: "#22C55E" }).catch(() => {});
          chrome.action.setBadgeText({ tabId: tId, text: "OK" }).catch(() => {});
        }
      };

      if (tabId) {
        applyBadge(tabId);
      } else {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            applyBadge(tabs[0].id);
          }
        });
      }
    });
  }
});

// Listener to clear badge immediately when settings are updated in the dashboard
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === "local" && changes.settings) {
    const newSettings = changes.settings.newValue || {};
    const controls = newSettings.controls || { autoScan: true, popupAlerts: true, overlayAlerts: true };
    if (!controls.popupAlerts) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.action.setBadgeText({ tabId: tabs[0].id, text: "" }).catch(() => {});
        }
      });
    }
  }
});