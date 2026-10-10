try { chrome.storage.local.set({ offscreen_loaded: Date.now() }); } catch (e) {}
// Error reporter for the offscreen document — must be a classic script so it
// runs even when the module import itself fails.
window.addEventListener('error', (e) => {
  try { chrome.runtime.sendMessage({ type: 'OFFSCREEN_ERROR', message: String(e.message || 'unknown') }); } catch (err) {}
});
window.addEventListener('unhandledrejection', (e) => {
  try { chrome.runtime.sendMessage({ type: 'OFFSCREEN_ERROR', message: String(e.reason && e.reason.message || e.reason) }); } catch (err) {}
});
