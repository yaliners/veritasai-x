(async () => {
  try {
    const src = chrome.runtime.getURL("content-main.js");
    await import(src);
  } catch (e) {
    console.warn("Failed to load VeritasShield main module:", e.message);
  }
})();
