module.exports = {
  testDir: './e2e',
  timeout: 60000,
  globalTimeout: 12 * 60 * 1000,
  actionTimeout: 15000,
  navigationTimeout: 15000,
  expect: { timeout: 15000 },
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list']]
};
