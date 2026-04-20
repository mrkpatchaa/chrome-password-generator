'use strict';

// ── Character Sets ─────────────────────────────────────────
const CHARS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers:   '0123456789',
  symbols:   '!@#$%^&*()-_=+[]{}|;:,.<>?',
};

// Ambiguous characters to optionally strip
const AMBIGUOUS = /[0OlI1]/g;

// ── Secure Random ──────────────────────────────────────────
/**
 * Returns a cryptographically secure integer in [0, max).
 * Uses rejection sampling to eliminate modulo bias.
 */
function secureRandInt(max) {
  const buf = new Uint32Array(1);
  const limit = 2 ** 32 - (2 ** 32 % max);
  let value;
  do {
    crypto.getRandomValues(buf);
    value = buf[0];
  } while (value >= limit);
  return value % max;
}

// ── Password Generation ────────────────────────────────────
function generatePassword(length, opts) {
  // Build the active charset and track required sets
  let charset = '';
  const required = [];

  for (const key of ['uppercase', 'lowercase', 'numbers', 'symbols']) {
    if (!opts[key]) continue;
    let chars = CHARS[key];
    if (opts.noAmbiguous) chars = chars.replace(AMBIGUOUS, '');
    if (!chars) continue;
    charset += chars;
    required.push(chars);
  }

  if (!charset || required.length === 0) return null;

  // Guarantee one character from every required set, then fill randomly
  const passwordChars = [];

  for (const chars of required) {
    passwordChars.push(chars[secureRandInt(chars.length)]);
  }

  while (passwordChars.length < length) {
    passwordChars.push(charset[secureRandInt(charset.length)]);
  }

  // Fisher-Yates shuffle (secure)
  for (let i = passwordChars.length - 1; i > 0; i--) {
    const j = secureRandInt(i + 1);
    [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
  }

  return passwordChars.join('');
}

// ── Strength Estimation ────────────────────────────────────
function calcStrength(password, opts) {
  if (!password) return { level: 0, label: '—' };

  const len = password.length;
  const pools = [
    opts.uppercase && /[A-Z]/.test(password) ? 26 : 0,
    opts.lowercase && /[a-z]/.test(password) ? 26 : 0,
    opts.numbers   && /[0-9]/.test(password) ? 10 : 0,
    opts.symbols   && /[^A-Za-z0-9]/.test(password) ? 32 : 0,
  ].filter(Boolean);

  const poolSize = pools.reduce((a, b) => a + b, 0);
  const entropy  = len * Math.log2(poolSize || 1);

  const levels = [
    { min: 0,  level: 1, label: 'Weak'   },
    { min: 40, level: 2, label: 'Fair'   },
    { min: 56, level: 3, label: 'Good'   },
    { min: 72, level: 4, label: 'Strong' },
    { min: 96, level: 5, label: 'Max'    },
  ];

  const result = levels.reduce((acc, cur) => entropy >= cur.min ? cur : acc);
  return result;
}

// ── DOM Refs ───────────────────────────────────────────────
const passwordText  = document.getElementById('password-text');
const copyBtn       = document.getElementById('copy-btn');
const copyIcon      = document.getElementById('copy-icon');
const checkIcon     = document.getElementById('check-icon');
const strengthFill  = document.getElementById('strength-fill');
const strengthLabel = document.getElementById('strength-label');
const lengthSlider  = document.getElementById('length-slider');
const lengthDisplay = document.getElementById('length-display');
const generateBtn   = document.getElementById('generate-btn');

const optUppercase    = document.getElementById('opt-uppercase');
const optLowercase    = document.getElementById('opt-lowercase');
const optNumbers      = document.getElementById('opt-numbers');
const optSymbols      = document.getElementById('opt-symbols');
const optNoAmbiguous  = document.getElementById('opt-no-ambiguous');

// ── State ──────────────────────────────────────────────────
let currentPassword = '';
let copyTimeout     = null;

// ── Helpers ────────────────────────────────────────────────
function getOpts() {
  return {
    uppercase:   optUppercase.checked,
    lowercase:   optLowercase.checked,
    numbers:     optNumbers.checked,
    symbols:     optSymbols.checked,
    noAmbiguous: optNoAmbiguous.checked,
  };
}

function atLeastOneChecked() {
  return optUppercase.checked || optLowercase.checked ||
         optNumbers.checked   || optSymbols.checked;
}

function updateStrength(password) {
  if (!password) {
    strengthFill.removeAttribute('data-level');
    strengthLabel.removeAttribute('data-level');
    strengthLabel.textContent = '—';
    return;
  }
  const { level, label } = calcStrength(password, getOpts());
  strengthFill.setAttribute('data-level', level);
  strengthLabel.setAttribute('data-level', level);
  strengthLabel.textContent = label;
}

function setPassword(pwd) {
  currentPassword = pwd;
  passwordText.textContent = pwd;
  passwordText.classList.remove('placeholder');
  copyBtn.disabled = false;
  updateStrength(pwd);
}

// ── Generate ───────────────────────────────────────────────
function handleGenerate() {
  if (!atLeastOneChecked()) {
    // Pulse the toggles to hint the user
    document.querySelector('.toggles-grid').animate(
      [{ opacity: 1 }, { opacity: 0.3 }, { opacity: 1 }],
      { duration: 400, easing: 'ease-in-out' }
    );
    return;
  }

  const length = parseInt(lengthSlider.value, 10);
  const opts   = getOpts();
  const pwd    = generatePassword(length, opts);

  if (pwd) {
    setPassword(pwd);
    // Subtle flash on the password box
    passwordText.animate(
      [{ opacity: 0.4 }, { opacity: 1 }],
      { duration: 200, easing: 'ease-out' }
    );
  }
}

// ── Copy ───────────────────────────────────────────────────
async function handleCopy() {
  if (!currentPassword) return;

  try {
    await navigator.clipboard.writeText(currentPassword);

    // Show checkmark
    copyBtn.classList.add('copied');
    copyIcon.classList.add('hidden');
    checkIcon.classList.remove('hidden');

    // Reset after 1.8 s
    clearTimeout(copyTimeout);
    copyTimeout = setTimeout(() => {
      copyBtn.classList.remove('copied');
      copyIcon.classList.remove('hidden');
      checkIcon.classList.add('hidden');
    }, 1800);
  } catch (err) {
    // Fallback: execCommand (deprecated but works in some extension contexts)
    const el = document.createElement('textarea');
    el.value = currentPassword;
    el.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
  }
}

// ── Slider ─────────────────────────────────────────────────
function updateSliderTrack() {
  const min = parseInt(lengthSlider.min, 10);
  const max = parseInt(lengthSlider.max, 10);
  const val = parseInt(lengthSlider.value, 10);
  const pct = ((val - min) / (max - min)) * 100;
  lengthSlider.style.background =
    `linear-gradient(to right, #7c3aed ${pct}%, var(--surface-2) ${pct}%)`;
  lengthDisplay.textContent = val;
}

// ── Event Listeners ────────────────────────────────────────
generateBtn.addEventListener('click', handleGenerate);
copyBtn.addEventListener('click', handleCopy);

lengthSlider.addEventListener('input', () => {
  updateSliderTrack();
  // Live-update if a password already exists
  if (currentPassword) handleGenerate();
});

// Regenerate on option change (if a password exists)
[optUppercase, optLowercase, optNumbers, optSymbols, optNoAmbiguous].forEach(el => {
  el.addEventListener('change', () => {
    if (currentPassword) handleGenerate();
  });
});

// Keyboard shortcut: Enter to generate, Ctrl+C to copy
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleGenerate();
  if ((e.ctrlKey || e.metaKey) && e.key === 'c' && currentPassword) handleCopy();
});

// ── Init ───────────────────────────────────────────────────
updateSliderTrack();
// Auto-generate on open
handleGenerate();
