/* ============================================================
   SecureID — app.js
   ------------------------------------------------------------
   Registration + login + MFA journey. Two pieces are REAL, not
   simulated:

   1. EMAIL DELIVERY — via a tiny Vercel serverless function at
      /api/send-otp (see api/send-otp.js), which sends the actual
      email through Resend (resend.com). The API key stays on the
      server, never in this file. Until you deploy it with a real
      RESEND_API_KEY, sendOtpEmail() below simply fails and every
      screen falls back to "demo mode", showing the code on-screen
      so the flow still works end-to-end.

   2. AUTHENTICATOR MFA — a real RFC 6238 TOTP implementation
      (HMAC-SHA1, 30s period, 6 digits — same defaults Google
      Authenticator/Authy use) built on the browser's native
      Web Crypto API. Scan the QR code with a real authenticator
      app and its codes will actually verify here. This needs a
      secure context (https://, or http://localhost) — Web
      Crypto is unavailable on a plain file:// page.

   SMS is still simulated — a real SMS OTP would plug a gateway
   like Twilio into the same /api pattern used for email.

   Data kept in localStorage:
     secureid_users     -> array of registered accounts
     secureid_pending   -> the account currently being registered
     secureid_login     -> the login attempt currently in progress

   Read this file top to bottom — every screen's logic lives in
   its own init function at the bottom, wired up by page id.
   ============================================================ */

const DB_USERS   = "secureid_users";
const PENDING_REG = "secureid_pending";
const PENDING_LOGIN = "secureid_login";

const OTP_TTL_SECONDS    = 180; // 3 minutes, matches "Code expires in 02:45" style screens
const RESEND_COOLDOWN    = 25;  // matches "Resend code (00:25)"
const MAX_OTP_ATTEMPTS   = 3;   // matches the "Max Attempts" screens

/* ---------------- tiny storage helpers ---------------- */
const store = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) { return fallback; }
  },
  set(key, value) { localStorage.setItem(key, JSON.stringify(value)); },
  remove(key) { localStorage.removeItem(key); }
};

function getUsers() { return store.get(DB_USERS, []); }
function saveUsers(users) { store.set(DB_USERS, users); }
function findUserByEmail(email) {
  return getUsers().find(u => u.email.toLowerCase() === email.toLowerCase());
}

/* ---------------- OTP helpers ---------------- */
function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Creates a fresh OTP challenge object, stored inline in whatever
// pending record it belongs to (pending registration or pending login).
function newOtpChallenge() {
  return {
    code: genOtp(),
    expiresAt: Date.now() + OTP_TTL_SECONDS * 1000,
    resendAvailableAt: Date.now() + RESEND_COOLDOWN * 1000,
    attemptsLeft: MAX_OTP_ATTEMPTS,
    locked: false
  };
}


function formatMMSS(totalSeconds) {
  const s = Math.max(0, Math.ceil(totalSeconds));
  const m = String(Math.floor(s / 60)).padStart(2, "0");
  const r = String(s % 60).padStart(2, "0");
  return `${m}:${r}`;
}

function maskEmail(email) {
  const [name, domain] = email.split("@");
  if (!domain) return email;
  const visible = name.slice(0, 2);
  return `${visible}${"*".repeat(Math.max(name.length - 2, 2))}@${domain}`;
}

function maskPhone(phone) {
  const digits = phone.replace(/\D/g, "");
  return `+${digits.slice(0, 2)} ${"*".repeat(Math.max(digits.length - 6, 4))}${digits.slice(-4)}`;
}

/* ---------------- real email sending ----------------
   Calls a tiny Vercel serverless function (api/send-otp.js) which sends
   the actual email through Resend. See api/send-otp.js + README for the
   one env var you need to set (RESEND_API_KEY) to make this live.

   If the API isn't deployed/configured yet (e.g. you're opening the
   files locally, or haven't added the key), this simply fails silently
   and the on-screen demo banner is used as a fallback — the flow never
   breaks, it just falls back to "demo mode" until email is wired up.
------------------------------------------------------------- */
async function sendOtpEmail(email, code) {
  try {
    const res = await fetch("/api/send-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code })
    });
    return res.ok;
  } catch (e) {
    return false; // no backend reachable (local file:// preview, or not deployed yet)
  }
}

/* ---------------- real TOTP (RFC 6238) ----------------
   This is the exact algorithm Google Authenticator / Authy use, run
   entirely client-side via the Web Crypto API — no library, no backend.
   A code generated here from the secret in the QR code will genuinely
   match what the user's authenticator app shows.
------------------------------------------------------------- */
function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32.replace(/=+$/, "").toUpperCase()) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}

async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

function counterToBytes(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(4, counter, false); // big-endian; high 4 bytes are 0 (counter fits in 32 bits until year 2106)
  return new Uint8Array(buf);
}

async function generateTOTP(secretBase32, { step = 30, digits = 6, offset = 0 } = {}) {
  const counter = Math.floor(Date.now() / 1000 / step) + offset;
  const hmac = await hmacSha1(base32Decode(secretBase32), counterToBytes(counter));
  const lastByte = hmac[hmac.length - 1];
  const o = lastByte & 0xf;
  const binCode =
    ((hmac[o] & 0x7f) << 24) | ((hmac[o + 1] & 0xff) << 16) | ((hmac[o + 2] & 0xff) << 8) | (hmac[o + 3] & 0xff);
  return String(binCode % 10 ** digits).padStart(digits, "0");
}

// Checks the entered code against the current 30s window plus one step
// either side, so a code the user was already typing as it rotated still
// verifies correctly.
async function verifyTOTP(secretBase32, token, window = 1) {
  for (let w = -window; w <= window; w++) {
    if ((await generateTOTP(secretBase32, { offset: w })) === token) return true;
  }
  return false;
}

/* ---------------- registration stepper ----------------
   5 steps: 1 Register, 2 Email OTP, 3 Mobile OTP, 4 MFA, 5 Success
------------------------------------------------------------- */
function renderStepper(containerId, currentStep) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const total = 5;
  let html = "";
  for (let i = 1; i <= total; i++) {
    const state = i < currentStep ? "done" : i === currentStep ? "current" : "";
    html += `<span class="dot ${state}">${i < currentStep ? "✓" : i}</span>`;
    if (i < total) html += `<span class="bar ${i < currentStep ? "done" : ""}"></span>`;
  }
  el.innerHTML = html;
}

/* ---------------- password strength ---------------- */
// Returns { score: 0-4, label, requirements: {len, upperLower, number, special} }
function checkPassword(pw) {
  const requirements = {
    len: pw.length >= 8,
    upperLower: /[a-z]/.test(pw) && /[A-Z]/.test(pw),
    number: /[0-9]/.test(pw),
    special: /[^A-Za-z0-9]/.test(pw)
  };
  const metCount = Object.values(requirements).filter(Boolean).length;
  let label = "weak";
  if (metCount === 4) label = "strong";
  else if (metCount >= 2) label = "medium";
  return { score: metCount, label, requirements, valid: metCount === 4 };
}

/* ---------------- generic redirect guards ---------------- */
// Call at the top of a step page to make sure the user actually
// came from the previous step, instead of loading the URL directly.
function requirePending(redirectTo) {
  const pending = store.get(PENDING_REG);
  if (!pending) { window.location.href = redirectTo || "register.html"; return null; }
  return pending;
}
function requireLoginPending(redirectTo) {
  const pending = store.get(PENDING_LOGIN);
  if (!pending) { window.location.href = redirectTo || "login.html"; return null; }
  return pending;
}

/* ---------------- shared 6-box OTP input wiring ----------------
   Used by both initOtpScreen (expiring codes) and initTotpScreen
   (live authenticator codes) so the box-to-box/paste behavior only
   has to be written once.
------------------------------------------------------------- */
function wireOtpBoxes(boxes, onComplete) {
  boxes.forEach((box, i) => {
    box.addEventListener("input", () => {
      box.value = box.value.replace(/\D/g, "").slice(0, 1);
      if (box.value && boxes[i + 1]) boxes[i + 1].focus();
      if (boxes.every(b => b.value)) onComplete();
    });
    box.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !box.value && boxes[i - 1]) boxes[i - 1].focus();
    });
    box.addEventListener("paste", (e) => {
      e.preventDefault();
      const digits = (e.clipboardData.getData("text").match(/\d/g) || []).slice(0, boxes.length);
      digits.forEach((d, idx) => { if (boxes[idx]) boxes[idx].value = d; });
      if (digits.length) boxes[Math.min(digits.length, boxes.length) - 1].focus();
      if (boxes.every(b => b.value)) onComplete();
    });
  });
}

/* ---------------- generic OTP-screen controller ----------------
   Reused by verify-email / verify-mobile / login-otp / mfa-verify
   for every EXPIRING, randomly-generated code (email/SMS OTPs).
   opts:
     getChallenge()      -> current challenge object (from pending record)
     saveChallenge(c)     -> persist mutated challenge back to storage
     onSuccess()          -> called once the right code is entered
     destinationLabel     -> text like "priya.sharma@email.com"
     sendCode(code)        -> optional async fn; when provided, actually
                              sends the code (e.g. via sendOtpEmail) instead
                              of just showing it in the demo banner
------------------------------------------------------------- */
function initOtpScreen(opts) {
  const boxes = Array.from(document.querySelectorAll(".otp-row input"));
  const statusEl = document.getElementById("otpStatus");
  const bannerEl = document.getElementById("otpBanner");
  const resendLink = document.getElementById("resendLink");
  const resendTimer = document.getElementById("resendTimer");
  const resendBtn = document.getElementById("resendBtn"); // full-width button, shown on expiry/lockout
  const continueBtn = document.getElementById("continueBtn");
  const destEl = document.getElementById("destination");

  if (destEl && opts.destinationLabel) destEl.textContent = opts.destinationLabel;

  function render() {
    const c = opts.getChallenge();
    const now = Date.now();
    const msLeft = c.expiresAt - now;
    const blocked = c.locked || msLeft <= 0;

    if (c.locked) {
      bannerEl.className = "otp-banner locked";
      bannerEl.textContent = "Maximum attempts reached. Please request a new code.";
      bannerEl.style.display = "block";
      statusEl.style.display = "none";
    } else if (msLeft <= 0) {
      bannerEl.style.display = "none";
      statusEl.style.display = "block";
      statusEl.className = "otp-status expired";
      statusEl.textContent = "Code expired.";
    } else {
      bannerEl.style.display = "none";
      statusEl.style.display = "block";
      statusEl.className = "otp-status";
      statusEl.innerHTML = `Code expires in <span class="timer">${formatMMSS(msLeft / 1000)}</span>`;
    }
    boxes.forEach(b => (b.disabled = blocked));
    continueBtn.disabled = blocked;

    const resendWait = c.resendAvailableAt - now;
    const resendReady = resendWait <= 0;

    // While the code is still live, "resend" is a small text link with a
    // cooldown. Once it's expired or locked, swap to a full-width button —
    // matches the mockups' "Resend New Code" / "Resend code" button states.
    if (resendBtn) {
      resendBtn.classList.toggle("show", blocked);
      resendBtn.disabled = !resendReady;
    }
    if (resendLink) resendLink.closest(".resend-row")?.classList.toggle("hidden-row", blocked && resendBtn);
    if (!blocked || !resendBtn) {
      if (resendWait > 0) {
        resendLink.classList.add("disabled");
        resendTimer.textContent = ` (${formatMMSS(resendWait / 1000)})`;
      } else {
        resendLink.classList.remove("disabled");
        resendTimer.textContent = "";
      }
    }
  }

  const tick = setInterval(render, 1000);
  render();

  wireOtpBoxes(boxes, tryVerify);

  function tryVerify() {
    const c = opts.getChallenge();
    const entered = boxes.map(b => b.value).join("");
    const now = Date.now();

    if (c.locked || now > c.expiresAt) { render(); return; }

    if (entered === c.code) {
      clearInterval(tick);
      opts.onSuccess();
      return;
    }

    c.attemptsLeft -= 1;
    if (c.attemptsLeft <= 0) {
      c.locked = true;
      opts.saveChallenge(c);
      render();
      return;
    }
    opts.saveChallenge(c);
    bannerEl.className = "otp-banner error";
    bannerEl.textContent = `Incorrect code. Please try again. You have ${c.attemptsLeft} attempt${c.attemptsLeft === 1 ? "" : "s"} left.`;
    bannerEl.style.display = "block";
    boxes.forEach(b => { b.value = ""; b.classList.add("field-error"); });
    boxes[0].focus();
    setTimeout(() => boxes.forEach(b => b.classList.remove("field-error")), 600);
  }

  continueBtn.addEventListener("click", tryVerify);

  function doResend() {
    const fresh = newOtpChallenge();
    opts.saveChallenge(fresh);
    boxes.forEach(b => { b.value = ""; b.disabled = false; });
    boxes[0].focus();
    announceCode(fresh.code);
    render();
  }

  resendLink.addEventListener("click", (e) => {
    e.preventDefault();
    if (resendLink.classList.contains("disabled")) return;
    doResend();
  });

  if (resendBtn) {
    resendBtn.addEventListener("click", () => {
      if (resendBtn.disabled) return;
      doResend();
    });
  }

  // If the page passed a real `sendCode` (e.g. sendOtpEmail), actually send
  // it and tell the user to check their inbox. Otherwise — or if sending
  // fails, such as the API not being deployed/configured yet — fall back
  // to showing the code on screen so the flow is always testable.
  announceCode(opts.getChallenge().code);
  async function announceCode(code) {
    const demo = document.getElementById("demoBanner");
    if (!demo) return;
    if (opts.sendCode) {
      demo.textContent = "Sending code…";
      const ok = await opts.sendCode(code);
      demo.innerHTML = ok
        ? `Code sent — check your inbox (and spam folder).`
        : `Email sending isn't configured yet — demo code: <b>${code}</b>`;
    } else {
      demo.innerHTML = `Demo mode — no real message sent. Your code is <b>${code}</b>`;
    }
  }
}

/* ---------------- authenticator-app (TOTP) screen controller ----------------
   Used by mfa-verify.html and login-otp.html when the account's MFA
   method is "authenticator". Unlike initOtpScreen, there's no stored
   code and no expiry/resend — the code is derived live from the shared
   secret every 30 seconds, exactly like the user's authenticator app.
   opts: { secret, onSuccess }
------------------------------------------------------------- */
function initTotpScreen(opts) {
  const boxes = Array.from(document.querySelectorAll(".otp-row input"));
  const statusEl = document.getElementById("otpStatus");
  const bannerEl = document.getElementById("otpBanner");
  const continueBtn = document.getElementById("continueBtn");
  const STEP = 30;

  function renderCountdown() {
    const secsLeft = STEP - (Math.floor(Date.now() / 1000) % STEP);
    statusEl.style.display = "block";
    statusEl.className = "otp-status";
    statusEl.innerHTML = `Code refreshes in <span class="timer">${secsLeft}s</span>`;
  }
  const tick = setInterval(renderCountdown, 1000);
  renderCountdown();

  wireOtpBoxes(boxes, tryVerify);
  continueBtn.addEventListener("click", tryVerify);

  async function tryVerify() {
    const entered = boxes.map(b => b.value).join("");
    if (entered.length < 6) return;
    continueBtn.disabled = true;
    const ok = await verifyTOTP(opts.secret, entered);
    continueBtn.disabled = false;
    if (ok) {
      clearInterval(tick);
      opts.onSuccess();
      return;
    }
    bannerEl.className = "otp-banner error";
    bannerEl.textContent = "Invalid code. Please try again.";
    bannerEl.style.display = "block";
    boxes.forEach(b => { b.value = ""; b.classList.add("field-error"); });
    boxes[0].focus();
    setTimeout(() => boxes.forEach(b => b.classList.remove("field-error")), 600);
  }
}

/* ============================================================
   PAGE: register.html
   ============================================================ */
function initRegisterPage() {
  renderStepper("stepper", 1);
  const form = document.getElementById("registerForm");
  const pwInput = document.getElementById("password");
  const confirmInput = document.getElementById("confirmPassword");
  const meterBars = document.querySelectorAll(".strength-meter span");
  const strengthLabel = document.getElementById("strengthLabel");
  const reqItems = {
    len: document.getElementById("req-len"),
    upperLower: document.getElementById("req-upperLower"),
    number: document.getElementById("req-number"),
    special: document.getElementById("req-special")
  };

  document.querySelectorAll(".toggle-visibility").forEach(btn => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.target);
      input.type = input.type === "password" ? "text" : "password";
    });
  });

  pwInput.addEventListener("input", () => {
    const result = checkPassword(pwInput.value);
    meterBars.forEach((bar, i) => {
      bar.style.background = i < result.score ? colorFor(result.label) : "";
    });
    strengthLabel.textContent = pwInput.value ? `Strength: ${capitalize(result.label)}` : "";
    strengthLabel.className = `strength-label ${result.label}`;
    Object.entries(result.requirements).forEach(([key, met]) => {
      reqItems[key].classList.toggle("met", met);
    });
  });

  function colorFor(label) {
    return { weak: "var(--red-600)", medium: "var(--amber-600)", strong: "var(--green-600)" }[label];
  }
  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearErrors(form);

    const name = form.fullName.value.trim();
    const phone = `${form.countryCode.value}${form.phone.value.trim()}`;
    const email = form.email.value.trim();
    const password = pwInput.value;
    const confirm = confirmInput.value;
    const agreed = form.terms.checked;

    let ok = true;
    if (!name) ok = fieldError("fullName", "Enter your full name") && false;
    if (!/^\d{7,15}$/.test(phone.replace(/\D/g, ""))) ok = fieldError("phone", "Enter a valid phone number") && false;
    if (!/^\S+@\S+\.\S+$/.test(email)) ok = fieldError("email", "Enter a valid email address") && false;
    if (findUserByEmail(email)) ok = fieldError("email", "An account with this email already exists") && false;
    if (!checkPassword(password).valid) ok = fieldError("password", "Password does not meet the requirements above") && false;
    if (password !== confirm) ok = fieldError("confirmPassword", "Passwords do not match") && false;
    if (!agreed) ok = fieldError("terms", "You must accept the Terms & Conditions to continue") && false;

    if (!ok) return;

    // Stash the in-progress registration and kick off email verification.
    const pending = {
      name, phone, email, password, // NOTE: demo only — never store plaintext passwords in a real app
      emailOtp: newOtpChallenge(),
      mobileOtp: null,
      mfaMethod: null,
      mfaSecret: null
    };
    store.set(PENDING_REG, pending);
    window.location.href = "verify-email.html";
  });

  function fieldError(name, message) {
    const input = form[name];
    input.classList && input.classList.add("field-error");
    const err = document.getElementById(`err-${name}`);
    if (err) { err.textContent = message; err.classList.add("show"); }
    return true; // returns truthy so the `= fieldError(...) && false` pattern reads cleanly above
  }
  function clearErrors(form) {
    form.querySelectorAll(".field-error").forEach(el => el.classList.remove("field-error"));
    form.querySelectorAll(".error-text").forEach(el => el.classList.remove("show"));
  }
}

/* ============================================================
   PAGE: verify-email.html
   ============================================================ */
function initVerifyEmailPage() {
  const pending = requirePending("register.html");
  if (!pending) return;
  renderStepper("stepper", 2);

  initOtpScreen({
    destinationLabel: maskEmail(pending.email),
    getChallenge: () => store.get(PENDING_REG).emailOtp,
    saveChallenge: (c) => {
      const p = store.get(PENDING_REG);
      p.emailOtp = c;
      store.set(PENDING_REG, p);
    },
    sendCode: (code) => sendOtpEmail(pending.email, code),
    onSuccess: () => {
      const p = store.get(PENDING_REG);
      p.mobileOtp = newOtpChallenge();
      store.set(PENDING_REG, p);
      window.location.href = "verify-mobile.html";
    }
  });
}

/* ============================================================
   PAGE: verify-mobile.html
   ============================================================ */
function initVerifyMobilePage() {
  const pending = requirePending("register.html");
  if (!pending) return;
  renderStepper("stepper", 3);

  initOtpScreen({
    destinationLabel: maskPhone(pending.phone),
    getChallenge: () => store.get(PENDING_REG).mobileOtp,
    saveChallenge: (c) => {
      const p = store.get(PENDING_REG);
      p.mobileOtp = c;
      store.set(PENDING_REG, p);
    },
    onSuccess: () => { window.location.href = "mfa-setup.html"; }
  });
}

/* ============================================================
   PAGE: mfa-setup.html  (choose authenticator / SMS / email)
   ============================================================ */
function initMfaSetupPage() {
  const pending = requirePending("register.html");
  if (!pending) return;
  renderStepper("stepper", 4);

  const methods = document.querySelectorAll(".method");
  const continueBtn = document.getElementById("continueBtn");
  let selected = "authenticator";

  methods.forEach(m => {
    m.addEventListener("click", () => {
      methods.forEach(x => x.classList.remove("selected"));
      m.classList.add("selected");
      m.querySelector("input").checked = true;
      selected = m.dataset.method;
    });
  });

  continueBtn.addEventListener("click", () => {
    const p = store.get(PENDING_REG);
    p.mfaMethod = selected;
    if (selected === "authenticator") {
      p.mfaSecret = genBase32Secret();
      store.set(PENDING_REG, p);
      window.location.href = "mfa-qr.html";
    } else {
      p.mfaOtp = newOtpChallenge();
      store.set(PENDING_REG, p);
      window.location.href = "mfa-verify.html";
    }
  });
}

function genBase32Secret(len = 16) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

/* ============================================================
   PAGE: mfa-qr.html  (scan QR / enter secret into authenticator)
   ============================================================ */
function initMfaQrPage() {
  const pending = requirePending("register.html");
  if (!pending) return;
  renderStepper("stepper", 4);

  document.getElementById("secretText").textContent = pending.mfaSecret;

  // The secret key stays hidden until the user says they can't scan the
  // QR code — matches the "Can't scan? Enter setup key" mockup.
  document.getElementById("setupKeyLink").addEventListener("click", (e) => {
    e.preventDefault();
    document.getElementById("secretText").style.display = "block";
    document.getElementById("setupKeyRow").style.display = "none";
  });

  const issuer = "SecureID";
  const label = encodeURIComponent(`${issuer}:${pending.email}`);
  const otpauth = `otpauth://totp/${label}?secret=${pending.mfaSecret}&issuer=${issuer}`;

  // QRCode.js draws directly into #qrcode (loaded via CDN in the page's <script> tag)
  // eslint-disable-next-line no-undef
  new QRCode(document.getElementById("qrcode"), {
    text: otpauth,
    width: 176,
    height: 176,
    colorDark: "#101828",
    colorLight: "#ffffff"
  });

  document.getElementById("continueBtn").addEventListener("click", () => {
    // Authenticator MFA is verified live via real TOTP (see mfa-verify.html /
    // initTotpScreen) — no stored challenge code is needed here.
    window.location.href = "mfa-verify.html";
  });
}

/* ============================================================
   PAGE: mfa-verify.html  (enter the 6-digit MFA code)
   ============================================================ */
function initMfaVerifyPage() {
  const pending = requirePending("register.html");
  if (!pending) return;
  renderStepper("stepper", 4);

  if (pending.mfaMethod === "authenticator") {
    // Real MFA: verified against the live TOTP code from the user's
    // actual authenticator app, not a stored/simulated value.
    document.getElementById("resendRow").style.display = "none";
    document.getElementById("demoBanner").style.display = "none";
    document.getElementById("destination").textContent = "your authenticator app";
    initTotpScreen({
      secret: pending.mfaSecret,
      onSuccess: () => finalizeRegistration()
    });
    return;
  }

  document.getElementById("resendRow").style.display = "block";
  initOtpScreen({
    destinationLabel: pending.mfaMethod === "email" ? maskEmail(pending.email) : maskPhone(pending.phone),
    getChallenge: () => store.get(PENDING_REG).mfaOtp,
    saveChallenge: (c) => {
      const p = store.get(PENDING_REG);
      p.mfaOtp = c;
      store.set(PENDING_REG, p);
    },
    sendCode: pending.mfaMethod === "email" ? (code) => sendOtpEmail(pending.email, code) : null,
    onSuccess: () => finalizeRegistration()
  });
}

// Registration complete: move the pending record into the real user table.
function finalizeRegistration() {
  const p = store.get(PENDING_REG);
  const users = getUsers();
  users.push({
    name: p.name,
    phone: p.phone,
    email: p.email,
    password: p.password, // demo only — never store plaintext passwords in a real app
    mfaMethod: p.mfaMethod,
    mfaSecret: p.mfaSecret || null
  });
  saveUsers(users);
  store.remove(PENDING_REG);
  window.location.href = "success.html";
}

/* ============================================================
   PAGE: success.html
   ============================================================ */
function initSuccessPage() {
  renderStepper("stepper", 5);
}

/* ============================================================
   PAGE: login.html
   ============================================================ */
function initLoginPage() {
  const form = document.getElementById("loginForm");
  const pwInput = document.getElementById("password");

  document.querySelectorAll(".toggle-visibility").forEach(btn => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.target);
      input.type = input.type === "password" ? "text" : "password";
    });
  });

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    clearErrors(form);

    const email = form.email.value.trim();
    const password = pwInput.value;
    const user = findUserByEmail(email);

    if (!user || user.password !== password) {
      fieldError("password", "Invalid email or password. Please try again.");
      form.email.classList.add("field-error");
      form.password.classList.add("field-error");
      document.getElementById("loginIcon").classList.add("error");
      return;
    }

    document.getElementById("loginIcon").classList.remove("error");
    store.set(PENDING_LOGIN, { email: user.email, method: null, otp: null });
    window.location.href = "login-choose-method.html";
  });

  function fieldError(name, message) {
    const err = document.getElementById(`err-${name}`);
    if (err) { err.textContent = message; err.classList.add("show"); }
  }
  function clearErrors(form) {
    form.querySelectorAll(".field-error").forEach(el => el.classList.remove("field-error"));
    form.querySelectorAll(".error-text").forEach(el => el.classList.remove("show"));
  }
}

/* ============================================================
   PAGE: login-choose-method.html
   ============================================================ */
function initLoginChooseMethodPage() {
  const pending = requireLoginPending();
  if (!pending) return;
  const user = findUserByEmail(pending.email);
  if (!user) { window.location.href = "login.html"; return; }

  // Only show the methods this account actually has available.
  document.querySelectorAll(".method").forEach(m => {
    const method = m.dataset.method;
    const available =
      method === "email" ||
      (method === "sms") ||
      (method === "authenticator" && user.mfaMethod === "authenticator");
    m.style.display = available ? "flex" : "none";
  });

  let selected = "email";
  document.querySelectorAll(".method").forEach(m => {
    if (m.style.display === "none") return;
    m.addEventListener("click", () => {
      document.querySelectorAll(".method").forEach(x => x.classList.remove("selected"));
      m.classList.add("selected");
      m.querySelector("input").checked = true;
      selected = m.dataset.method;
    });
  });

  document.getElementById("continueBtn").addEventListener("click", () => {
    const p = store.get(PENDING_LOGIN);
    p.method = selected;
    p.otp = newOtpChallenge();
    store.set(PENDING_LOGIN, p);
    window.location.href = "login-otp.html";
  });
}

/* ============================================================
   PAGE: login-otp.html
   ============================================================ */
function initLoginOtpPage() {
  const pending = requireLoginPending();
  if (!pending) return;
  const user = findUserByEmail(pending.email);
  if (!user) { window.location.href = "login.html"; return; }

  if (pending.method === "authenticator") {
    // Real MFA: verified against the live TOTP code from the user's
    // actual authenticator app, not a stored/simulated value.
    document.getElementById("resendRow").style.display = "none";
    document.getElementById("demoBanner").style.display = "none";
    document.getElementById("destination").textContent = "your authenticator app";
    initTotpScreen({
      secret: user.mfaSecret,
      onSuccess: () => finishLogin(user)
    });
    return;
  }

  const labelMap = { email: maskEmail(user.email), sms: maskPhone(user.phone) };
  document.getElementById("resendRow").style.display = "block";

  initOtpScreen({
    destinationLabel: labelMap[pending.method],
    getChallenge: () => store.get(PENDING_LOGIN).otp,
    saveChallenge: (c) => {
      const p = store.get(PENDING_LOGIN);
      p.otp = c;
      store.set(PENDING_LOGIN, p);
    },
    sendCode: pending.method === "email" ? (code) => sendOtpEmail(user.email, code) : null,
    onSuccess: () => finishLogin(user)
  });
}

function finishLogin(user) {
  store.remove(PENDING_LOGIN);
  store.set("secureid_session", { email: user.email, loggedInAt: Date.now() });
  window.location.href = "dashboard.html";
}

/* ============================================================
   PAGE: dashboard.html
   ============================================================ */
function initDashboardPage() {
  const session = store.get("secureid_session");
  if (!session) { window.location.href = "login.html"; return; }
  const user = findUserByEmail(session.email);
  document.getElementById("welcomeName").textContent = user ? user.name : session.email;

  document.getElementById("logoutBtn").addEventListener("click", () => {
    store.remove("secureid_session");
    window.location.href = "login.html";
  });
}

/* ============================================================
   Router: run the right init function for the current page
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  const map = {
    register: initRegisterPage,
    "verify-email": initVerifyEmailPage,
    "verify-mobile": initVerifyMobilePage,
    "mfa-setup": initMfaSetupPage,
    "mfa-qr": initMfaQrPage,
    "mfa-verify": initMfaVerifyPage,
    success: initSuccessPage,
    login: initLoginPage,
    "login-choose-method": initLoginChooseMethodPage,
    "login-otp": initLoginOtpPage,
    dashboard: initDashboardPage
  };
  if (map[page]) map[page]();
});
