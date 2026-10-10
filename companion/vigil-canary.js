#!/usr/bin/env node
/**
 * VIGIL Voice Canary — companion tool (Phase 4)
 *
 * The anti-deepfake core, usable today without any audio processing:
 * cloned voices cannot answer random personal challenges that were never
 * public. Before trusting an urgent "family member" call, generate a
 * challenge and ask it — a real person answers; a clone stonewalls,
 * deflects, or hangs up.
 *
 * Usage:
 *   node companion/vigil-canary.js                     # generic challenge
 *   node companion/vigil-canary.js --config=~/.vigil/canary.json
 *
 * Config file (optional): { "personals": ["the name of our first dog", ...] }
 * Rules of use are printed with every challenge.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const GENERIC_CHALLENGES = [
  'What did we eat the last time we had dinner together?',
  'Where did we go on our last family trip?',
  'What is the nickname only family uses for you?',
  'What was the last gift I gave you?',
  'Which relative do we both find impossible at holidays?',
  'What is the name of your first school teacher?',
  'What did you borrow from me last and never return?',
  'Which song do you always sing in the car?'
];

function loadConfig(configPath) {
  if (!configPath) return { personals: [] };
  const p = configPath.replace(/^~/, os.homedir());
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    return { personals: Array.isArray(j.personals) ? j.personals : [] };
  } catch (e) {
    return { personals: [] };
  }
}

/**
 * Generate one canary challenge. Personal questions take priority (a clone
 * has zero chance on family-only knowledge). Pure — exported for tests.
 */
function generateChallenge(config, rng) {
  const random = rng || Math.random;
  const personals = (config && config.personals) || [];
  if (personals.length) {
    return { type: 'personal', question: personals[Math.floor(random() * personals.length)] };
  }
  return { type: 'generic', question: GENERIC_CHALLENGES[Math.floor(random() * GENERIC_CHALLENGES.length)] };
}

function renderGuide(challenge) {
  return [
    '🛡️  VIGIL Voice Canary — caller verification',
    '',
    'ASK THE CALLER:', '"' + challenge.question + '"',
    '',
    'Rules of trust:',
    '  ✓ correct, specific answer          → likely the real person',
    '  ✗ vague, deflects, or gets angry    → treat as a voice clone: hang up',
    '  ✗ refuses and demands urgency/money → scam; call them back on the',
    '                                         number YOU have for them',
    '',
    'Why this works: cloned voices are built from public audio. They cannot',
    'answer questions that were never public. Challenge, then verify.'
  ].join('\n');
}

if (require.main === module) {
  const arg = process.argv.find(a => a.startsWith('--config='));
  const config = loadConfig(arg ? arg.split('=')[1] : path.join(os.homedir(), '.vigil', 'canary.json'));
  console.log(renderGuide(generateChallenge(config)));
}

module.exports = { generateChallenge, renderGuide, loadConfig, GENERIC_CHALLENGES };
