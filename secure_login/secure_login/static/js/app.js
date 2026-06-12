/* ── Password visibility toggle ──────────────────────────────────────── */
document.querySelectorAll('.field__eye').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    if (!target) return;
    const isText = target.type === 'text';
    target.type = isText ? 'password' : 'text';
    btn.querySelector('.eye-off').classList.toggle('hidden', !isText);
    btn.querySelector('.eye-on').classList.toggle('hidden', isText);
  });
});

/* ── Password strength meter ─────────────────────────────────────────── */
const pwInput     = document.getElementById('password');
const fills       = [1,2,3,4].map(n => document.getElementById(`sb-${n}`));
const strengthLbl = document.getElementById('strength-label');

const ruleLen   = document.getElementById('rule-len');
const ruleUpper = document.getElementById('rule-upper');
const ruleLower = document.getElementById('rule-lower');
const ruleDigit = document.getElementById('rule-digit');

function scorePassword(pw) {
  let score = 0;
  if (pw.length >= 8)          score++;
  if (pw.length >= 12)         score++;
  if (/[A-Z]/.test(pw))        score++;
  if (/[a-z]/.test(pw))        score++;
  if (/\d/.test(pw))           score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;
  // normalise to 0-4
  if (score <= 1) return 1;
  if (score <= 2) return 2;
  if (score <= 4) return 3;
  return 4;
}

const LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];
const COLORS = ['', '#F87171', '#FBBF24', '#60A5FA', '#34D399'];

function updateStrength() {
  if (!pwInput || !fills[0]) return;
  const pw    = pwInput.value;
  const score = pw.length ? scorePassword(pw) : 0;

  fills.forEach((f, i) => {
    if (score > i) {
      f.style.width           = '100%';
      f.style.backgroundColor = COLORS[score];
    } else {
      f.style.width           = '0';
    }
  });

  if (strengthLbl) {
    strengthLbl.textContent   = pw.length ? LABELS[score] : '';
    strengthLbl.style.color   = COLORS[score] || '';
  }

  // Rule indicators
  if (ruleLen)   ruleLen.classList.toggle('pass',   pw.length >= 8);
  if (ruleUpper) ruleUpper.classList.toggle('pass', /[A-Z]/.test(pw));
  if (ruleLower) ruleLower.classList.toggle('pass', /[a-z]/.test(pw));
  if (ruleDigit) ruleDigit.classList.toggle('pass', /\d/.test(pw));
}

if (pwInput) pwInput.addEventListener('input', updateStrength);

/* ── Password match indicator ────────────────────────────────────────── */
const confirmInput = document.getElementById('confirm_password');
const matchLabel   = document.getElementById('pw-match');

function checkMatch() {
  if (!pwInput || !confirmInput || !matchLabel) return;
  const pw  = pwInput.value;
  const cpw = confirmInput.value;
  if (!cpw) { matchLabel.textContent = ''; return; }
  if (pw === cpw) {
    matchLabel.textContent  = '✓ Passwords match';
    matchLabel.style.color  = '#34D399';
  } else {
    matchLabel.textContent  = '✕ Passwords do not match';
    matchLabel.style.color  = '#F87171';
  }
}

if (confirmInput) {
  confirmInput.addEventListener('input', checkMatch);
  if (pwInput) pwInput.addEventListener('input', checkMatch);
}

/* ── 2FA code auto-format (000 000) ──────────────────────────────────── */
const codeInput = document.getElementById('code');
if (codeInput) {
  codeInput.addEventListener('input', e => {
    let raw = e.target.value.replace(/\D/g, '').slice(0, 6);
    e.target.value = raw.length > 3 ? `${raw.slice(0,3)} ${raw.slice(3)}` : raw;
  });
  // Auto-submit when full code entered
  codeInput.addEventListener('input', e => {
    const digits = e.target.value.replace(/\D/g, '');
    if (digits.length === 6) {
      setTimeout(() => e.target.closest('form')?.submit(), 200);
    }
  });
}

/* ── Flash auto-dismiss ───────────────────────────────────────────────── */
setTimeout(() => {
  document.querySelectorAll('.flash').forEach(f => {
    f.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    f.style.opacity    = '0';
    f.style.transform  = 'translateX(20px)';
    setTimeout(() => f.remove(), 400);
  });
}, 4000);
