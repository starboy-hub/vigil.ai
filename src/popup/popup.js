/**
 * Vigil AI - Minimalist Dashboard (Popup)
 * Pure DOM implementation: fetches daily stats, handles 1-hour pause protection
 * with chrome.alarms, and lists recent activity.
 */

(function () {
  'use strict';

  let countdownInterval = null;

  document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
  });

  function $(id) {
    return document.getElementById(id);
  }

  function initDashboard() {
    setupSettingsButton();
    setupPauseButton();
    refreshData();

    // Listen for storage changes while popup is open
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local') {
          if (changes.vigil_history || changes.protection_paused || changes.protection_pause_until) {
            refreshData();
          }
        }
      });
    }

    // Refresh countdown every 10 seconds while open
    countdownInterval = setInterval(() => {
      checkPauseCountdown();
    }, 10000);

    window.addEventListener('unload', () => {
      if (countdownInterval) clearInterval(countdownInterval);
    });
  }

  function setupSettingsButton() {
    const btn = $('openOptions');
    if (!btn) return;
    btn.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      } else {
        window.open(chrome.runtime.getURL('options.html'));
      }
    });
  }

  function setupPauseButton() {
    const btn = $('pauseButton');
    if (!btn) return;

    btn.addEventListener('click', async () => {
      try {
        const stored = await getLocalStorage(['protection_paused', 'protection_pause_until']);
        const isPaused = stored.protection_paused && stored.protection_pause_until > Date.now();

        if (isPaused) {
          // Resume protection
          await setLocalStorage({
            protection_paused: false,
            protection_pause_until: 0
          });
          if (typeof chrome !== 'undefined' && chrome.alarms && chrome.alarms.clear) {
            chrome.alarms.clear('pause_protection');
          }
        } else {
          // Pause protection for 1 hour
          const pauseUntil = Date.now() + 60 * 60 * 1000;
          await setLocalStorage({
            protection_paused: true,
            protection_pause_until: pauseUntil
          });
          if (typeof chrome !== 'undefined' && chrome.alarms && chrome.alarms.create) {
            chrome.alarms.create('pause_protection', { delayInMinutes: 60 });
          }
        }
        refreshData();
      } catch (err) {
        console.warn('[VIGIL] Error toggling pause state:', err);
      }
    });
  }

  async function refreshData() {
    try {
      const stored = await getLocalStorage([
        'vigil_history',
        'vigil_summary',
        'protection_paused',
        'protection_pause_until'
      ]);

      const history = Array.isArray(stored.vigil_history) ? stored.vigil_history : [];
      const summary = stored.vigil_summary || null;

      // 1. Calculate and update daily threat count
      const stats = (typeof VIGIL !== 'undefined' && VIGIL.statsFromHistory)
        ? VIGIL.statsFromHistory(history, summary)
        : deriveLocalStats(history);

      updateStatsUI(stats.todayProtected);

      // 2. Update pause/protection status
      updatePauseUI(stored.protection_paused, stored.protection_pause_until);

      // 3. Render recent activity (last 3 items)
      renderRecentActivity(history);

    } catch (err) {
      console.warn('[VIGIL] Error refreshing popup data:', err);
    }
  }

  function deriveLocalStats(history) {
    const today = new Date().toDateString();
    let count = 0;
    history.forEach(item => {
      if (item && item.timestamp && new Date(item.timestamp).toDateString() === today) {
        count++;
      }
    });
    return { todayProtected: count };
  }

  function updateStatsUI(todayCount) {
    const countEl = $('threatCount');
    const labelEl = $('threatLabel');
    if (!countEl || !labelEl) return;

    countEl.textContent = String(todayCount);
    labelEl.textContent = todayCount === 1 ? 'Threat Blocked Today' : 'Threats Blocked Today';
  }

  function updatePauseUI(isPausedFlag, pauseUntil) {
    const btn = $('pauseButton');
    const statusText = $('statusText');
    const card = document.querySelector('.status-card');
    if (!btn || !statusText) return;

    const now = Date.now();
    const isPaused = !!isPausedFlag && pauseUntil && pauseUntil > now;

    if (isPaused) {
      const minsRemaining = Math.max(1, Math.ceil((pauseUntil - now) / 60000));
      btn.textContent = `Resuming in ${minsRemaining} min (Click to resume)`;
      btn.classList.add('paused');
      statusText.textContent = 'Protection Paused';
      if (card) card.classList.add('paused');
    } else {
      btn.textContent = 'Pause Protection (1 Hour)';
      btn.classList.remove('paused');
      statusText.textContent = 'Protection Active';
      if (card) card.classList.remove('paused');
    }
  }

  function checkPauseCountdown() {
    getLocalStorage(['protection_paused', 'protection_pause_until']).then(stored => {
      const isPaused = stored.protection_paused && stored.protection_pause_until > Date.now();
      if (isPaused) {
        updatePauseUI(true, stored.protection_pause_until);
      } else if (stored.protection_paused && stored.protection_pause_until <= Date.now()) {
        // Expired
        setLocalStorage({ protection_paused: false, protection_pause_until: 0 }).then(() => {
          updatePauseUI(false, 0);
        });
      }
    });
  }

  function renderRecentActivity(history) {
    const list = $('activityList');
    if (!list) return;

    // Clear existing items via pure DOM
    while (list.firstChild) {
      list.removeChild(list.firstChild);
    }

    if (!history || history.length === 0) {
      const emptyLi = document.createElement('li');
      emptyLi.className = 'activity-empty';
      emptyLi.textContent = 'No threats detected yet today';
      list.appendChild(emptyLi);
      return;
    }

    // Sort by timestamp descending and take the last 3 items
    const recent = history.slice().reverse().slice(0, 3);

    recent.forEach(item => {
      const li = document.createElement('li');
      li.className = 'activity-item';

      const infoDiv = document.createElement('div');
      infoDiv.className = 'activity-info';

      const typeSpan = document.createElement('span');
      typeSpan.className = 'activity-type';
      typeSpan.textContent = item.type || 'Sensitive Data';
      infoDiv.appendChild(typeSpan);

      const siteSpan = document.createElement('span');
      siteSpan.className = 'activity-site';
      siteSpan.textContent = item.site || 'Current Page';
      infoDiv.appendChild(siteSpan);

      li.appendChild(infoDiv);

      if (item.timestamp) {
        const timeSpan = document.createElement('span');
        timeSpan.className = 'activity-time';
        timeSpan.textContent = formatTimeAgo(item.timestamp);
        li.appendChild(timeSpan);
      }

      list.appendChild(li);
    });
  }

  function formatTimeAgo(timestamp) {
    if (!timestamp) return '';
    const diffSec = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000));
    if (diffSec < 60) return 'Just now';
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  }

  function getLocalStorage(keys) {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(keys, resolve);
      } else {
        resolve({});
      }
    });
  }

  function setLocalStorage(items) {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set(items, resolve);
      } else {
        resolve();
      }
    });
  }

  // Expose helpers for Jest test suite
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      deriveLocalStats,
      formatTimeAgo,
      updateStatsUI,
      updatePauseUI,
      renderRecentActivity
    };
  }
})();
