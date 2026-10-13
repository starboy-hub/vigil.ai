/**
 * Tests for Task 3: Dashboard (Popup) Redesign
 * Validates single-column status screen logic, daily threat counter,
 * pause protection state formatting, and recent activity rendering.
 */

const {
  deriveLocalStats,
  formatTimeAgo,
  updateStatsUI,
  updatePauseUI,
  renderRecentActivity
} = require('../src/popup/popup.js');

describe('Task 3: Popup Redesign', () => {

  describe('deriveLocalStats', () => {
    test('counts items matching today date correctly', () => {
      const now = new Date();
      const yesterday = new Date(Date.now() - 86400000 * 2);

      const history = [
        { timestamp: now.toISOString(), site: 'chatgpt.com', type: 'Email' },
        { timestamp: now.toISOString(), site: 'claude.ai', type: 'Credit Card' },
        { timestamp: yesterday.toISOString(), site: 'openai.com', type: 'SSN' }
      ];

      const stats = deriveLocalStats(history);
      expect(stats.todayProtected).toBe(2);
    });

    test('returns zero for empty history', () => {
      expect(deriveLocalStats([])).toEqual({ todayProtected: 0 });
    });
  });

  describe('formatTimeAgo', () => {
    test('formats time differences accurately', () => {
      const now = Date.now();
      expect(formatTimeAgo(new Date(now - 10000).toISOString())).toBe('Just now');
      expect(formatTimeAgo(new Date(now - 120000).toISOString())).toBe('2m ago');
      expect(formatTimeAgo(new Date(now - 7200000).toISOString())).toBe('2h ago');
      expect(formatTimeAgo(new Date(now - 86400000 * 3).toISOString())).toBe('3d ago');
      expect(formatTimeAgo(null)).toBe('');
    });
  });

  describe('updateStatsUI', () => {
    beforeEach(() => {
      document.body.innerHTML = `
        <div id="threatCount">0</div>
        <div id="threatLabel">Threats Blocked Today</div>
      `;
    });

    test('formats singular threat label correctly', () => {
      updateStatsUI(1);
      expect(document.getElementById('threatCount').textContent).toBe('1');
      expect(document.getElementById('threatLabel').textContent).toBe('Threat Blocked Today');
    });

    test('formats plural threats label correctly', () => {
      updateStatsUI(5);
      expect(document.getElementById('threatCount').textContent).toBe('5');
      expect(document.getElementById('threatLabel').textContent).toBe('Threats Blocked Today');
    });
  });

  describe('updatePauseUI', () => {
    beforeEach(() => {
      document.body.innerHTML = `
        <div class="status-card">
          <span id="statusText">Protection Active</span>
        </div>
        <button id="pauseButton">Pause Protection (1 Hour)</button>
      `;
    });

    test('reflects active protection state', () => {
      updatePauseUI(false, 0);
      const btn = document.getElementById('pauseButton');
      const status = document.getElementById('statusText');
      const card = document.querySelector('.status-card');

      expect(btn.textContent).toBe('Pause Protection (1 Hour)');
      expect(btn.classList.contains('paused')).toBe(false);
      expect(status.textContent).toBe('Protection Active');
      expect(card.classList.contains('paused')).toBe(false);
    });

    test('reflects paused protection state with remaining minutes', () => {
      const pauseUntil = Date.now() + 45 * 60 * 1000;
      updatePauseUI(true, pauseUntil);
      const btn = document.getElementById('pauseButton');
      const status = document.getElementById('statusText');
      const card = document.querySelector('.status-card');

      expect(btn.textContent).toContain('Resuming in 45 min');
      expect(btn.classList.contains('paused')).toBe(true);
      expect(status.textContent).toBe('Protection Paused');
      expect(card.classList.contains('paused')).toBe(true);
    });
  });

  describe('renderRecentActivity', () => {
    beforeEach(() => {
      document.body.innerHTML = `
        <ul id="activityList"></ul>
      `;
    });

    test('shows empty placeholder when history is empty', () => {
      renderRecentActivity([]);
      const list = document.getElementById('activityList');
      expect(list.children.length).toBe(1);
      expect(list.children[0].className).toBe('activity-empty');
      expect(list.children[0].textContent).toBe('No threats detected yet today');
    });

    test('renders only the last 3 items in descending order with Type, Site, and relative time', () => {
      const history = [
        { timestamp: new Date(Date.now() - 3600000).toISOString(), site: 'site1.com', type: 'Email' },
        { timestamp: new Date(Date.now() - 1800000).toISOString(), site: 'site2.com', type: 'API Key' },
        { timestamp: new Date(Date.now() - 600000).toISOString(), site: 'site3.com', type: 'Credit Card' },
        { timestamp: new Date(Date.now() - 60000).toISOString(), site: 'site4.com', type: 'Password' }
      ];

      renderRecentActivity(history);
      const list = document.getElementById('activityList');
      expect(list.children.length).toBe(3);

      // Most recent should be first
      const item0 = list.children[0];
      expect(item0.querySelector('.activity-type').textContent).toBe('Password');
      expect(item0.querySelector('.activity-site').textContent).toBe('site4.com');

      const item1 = list.children[1];
      expect(item1.querySelector('.activity-type').textContent).toBe('Credit Card');
      expect(item1.querySelector('.activity-site').textContent).toBe('site3.com');

      const item2 = list.children[2];
      expect(item2.querySelector('.activity-type').textContent).toBe('API Key');
      expect(item2.querySelector('.activity-site').textContent).toBe('site2.com');
    });
  });
});

