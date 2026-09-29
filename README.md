# SecureID — Registration & Login Journey

A registration + login flow from the assignment mockups: account
creation → email OTP → mobile OTP → MFA setup (Authenticator / SMS /
Email) → success → login → choose verification method → OTP →
dashboard.

**Email delivery and the Authenticator app are real**, not simulated:
email OTPs go out through a small Vercel serverless function (Resend),
and the authenticator code is checked with a genuine RFC 6238 TOTP
implementation that works with real apps like Google Authenticator.
See "Making email delivery real" and "Making the Authenticator app
real" below for the two-minute setup (or skip it — both fall back to
an on-screen demo mode automatically). SMS OTPs are still simulated.
State (users, in-progress registration/login) lives in the browser's
`localStorage`.

## File structure

```
secureid/
├── index.html                 redirects to login.html
├── register.html              Create account
├── verify-email.html          Email OTP
├── verify-mobile.html         Mobile OTP
├── mfa-setup.html             Choose MFA method
├── mfa-qr.html                Scan QR (authenticator only)
├── mfa-verify.html            Enter MFA code
├── success.html               Account created
├── login.html                 Email + password
├── login-choose-method.html   Choose OTP method for this login
├── login-otp.html             Enter OTP to finish login
├── dashboard.html             Logged-in placeholder page
├── css/style.css              One shared stylesheet for every screen
├── js/app.js                  All logic (see below)
└── api/send-otp.js            Vercel serverless function — sends real OTP emails via Resend
```

## How the code is organized (js/app.js)

Every page loads the same `js/app.js`. Each `<body>` tag has a
`data-page="..."` attribute; a small router at the bottom of `app.js`
calls the matching `initXxxPage()` function on load. That's the whole
"multi-page app" pattern:

```html
<body data-page="register">
```
```js
document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  const map = { register: initRegisterPage, /* ...one entry per page */ };
  if (map[page]) map[page]();
});
```

The logic is layered like this:

1. **Storage helpers** (`store.get/set/remove`) — thin wrapper around
   `localStorage` so the rest of the code never touches
   `JSON.stringify`/`parse` directly.
2. **Domain helpers** — `getUsers()`, `findUserByEmail()`,
   `genOtp()`, `newOtpChallenge()`, `checkPassword()`,
   `maskEmail()` / `maskPhone()`.
3. **`initOtpScreen(opts)`** — one reusable controller for every OTP
   screen (email, mobile, MFA, login). It handles: 6-box input +
   auto-advance + paste, the countdown timer, expiry, wrong-code
   attempts (locks after 3), and resend cooldown. Each page just
   tells it *where the current code is stored* and *what to do on
   success* — that's the `getChallenge` / `saveChallenge` /
   `onSuccess` options.
4. **Per-page `initXxxPage()` functions** — page-specific wiring
   (form validation, which button does what, where to redirect
   next).

### The registration flow, step by step

1. `register.html` validates the form (name, phone, email format,
   password strength via `checkPassword()`, matching confirm
   password, terms checkbox), then writes a `secureid_pending`
   object to `localStorage` with a fresh email OTP and redirects to
   `verify-email.html`.
2. `verify-email.html` reads `secureid_pending`, verifies the code via
   `initOtpScreen`, then generates a mobile OTP and redirects to
   `verify-mobile.html`.
3. `verify-mobile.html` verifies the mobile code, then redirects to
   `mfa-setup.html`.
4. `mfa-setup.html` lets the user pick Authenticator / SMS / Email.
   - Authenticator → generates a fake base32 secret, redirects to
     `mfa-qr.html` (renders a real scannable QR code using the
     `qrcodejs` library from a CDN, encoding a standard
     `otpauth://totp/...` URI) → then `mfa-verify.html`.
   - SMS / Email → generates an OTP directly and goes straight to
     `mfa-verify.html`.
5. `mfa-verify.html` verifies the final code, **moves the pending
   record into the real `secureid_users` list**, clears
   `secureid_pending`, and redirects to `success.html`.

### The login flow, step by step

1. `login.html` checks email + password against `secureid_users`. On
   success it writes a `secureid_login` object and goes to
   `login-choose-method.html`.
2. `login-choose-method.html` only shows the Authenticator option if
   that's what the account registered with. Picking a method
   generates a fresh OTP and goes to `login-otp.html`.
3. `login-otp.html` verifies the code (same `initOtpScreen`
   controller), then stores a `secureid_session` and redirects to
   `dashboard.html`.

## Running it locally

Email sending and the authenticator MFA both need real backend/crypto
support, so for this version use Vercel's local dev server rather than
a plain static file server:

```bash
npm install -g vercel   # one-time
cd secureid
vercel dev
```

Then open the URL it prints (typically `http://localhost:3000`).
(`npx serve .` still works for browsing the UI, but `/api/send-otp`
won't respond and everything will run in demo mode — that's fine too.)

## Making email delivery real (Resend + Vercel)

Email OTPs are sent through a tiny serverless function at
`api/send-otp.js`, using [Resend](https://resend.com) — free to start,
no credit card needed:

1. Create a Resend account → **API Keys** → create one (starts with `re_`).
2. In your Vercel project: **Settings → Environment Variables** → add
   `RESEND_API_KEY` = your key. Redeploy.
3. That's it. `sendOtpEmail()` in `js/app.js` calls `/api/send-otp`,
   which calls Resend — real emails start arriving for every
   registration/login/MFA step that uses email.
4. (Optional) verify your own sending domain in Resend and set
   `RESEND_FROM = "SecureID <noreply@yourdomain.com>"` as another env
   var — until then it sends from Resend's shared test address, which
   is fine for demoing.

**If you never set `RESEND_API_KEY`:** nothing breaks. Every OTP
screen automatically falls back to its on-screen "demo mode" banner,
so the whole flow still works end-to-end for grading/testing without
any account setup.

## Making the Authenticator app real (no setup needed)

This one needs no third-party account at all. `js/app.js` implements
**RFC 6238 TOTP** (the actual algorithm behind Google Authenticator /
Authy) using the browser's built-in Web Crypto API:

- `mfa-qr.html` generates a real random secret and encodes it into a
  standard `otpauth://totp/...` QR code.
- Scan it with a real authenticator app on your phone.
- The 6-digit code your phone shows will genuinely match what
  `verifyTOTP()` computes here — there's no simulation, no hard-coded
  answer.

The only requirement: this needs a **secure context** (`https://`, or
`http://localhost`) — `crypto.subtle` is unavailable on a plain
`file://` page, which is exactly why `vercel dev` (above) is the way
to run this locally instead of just double-clicking `index.html`.

## Deploying to Vercel

1. Push this folder (including the `api/` folder) to a GitHub repo.
2. Go to vercel.com → **New Project** → import the repo.
3. Framework preset: **Other** — no build command needed, leave
   "Build Command" and "Output Directory" blank. Vercel auto-detects
   `api/send-otp.js` as a serverless function; nothing else to configure.
4. Add the `RESEND_API_KEY` environment variable (see above) if you
   want real email — otherwise it'll run in demo mode.
5. Deploy. You'll get a URL like `your-name-secureid.vercel.app` —
   rename the project in Vercel's settings to match that pattern if
   the assignment expects it.

## What's simulated vs. what's real

| Feature | Status |
|---|---|
| Form validation, password strength | Real, client-side |
| Email OTP sending | **Real**, once `RESEND_API_KEY` is set (`api/send-otp.js` via Resend) — demo-mode fallback otherwise |
| SMS OTP sending | Simulated — a real one needs a paid gateway (e.g. Twilio), which would plug into the same `/api` pattern |
| OTP expiry, attempt limits, lockout, resend cooldown | Real, client-side timers |
| QR code | Real QR image, encodes a standard `otpauth://` URI |
| Authenticator code checking | **Real** — genuine RFC 6238 TOTP via Web Crypto, verifies against actual authenticator apps |
| User accounts, sessions | Stored in `localStorage`, not a real database |

## Extending this to Part 2 (password show/hide + strength meter)

That's already implemented on `register.html` — see `initRegisterPage()`
in `js/app.js` for the eye-icon toggle and the 4-bar strength meter
tied to `checkPassword()`.

## Matching the final mockups (Login_Screens.png / Registration_Screens.png)

These details were added to line the code up with the exact screens:

- **Stepper** (`renderStepper()` in `app.js`, `.stepper` in `style.css`) — a
  5-dot progress indicator (Register → Email → Mobile → MFA → Success) shown
  at the top of every registration-flow card.
- **Country-code dropdown** on `register.html` — `<select>` + number input
  side by side (`.phone-row`), combined into one `+91XXXXXXXXXX` value on
  submit.
- **"Wrong number? Change"** link on `verify-mobile.html`, back to
  `register.html`.
- **"Can't scan? Enter setup key"** on `mfa-qr.html` — the secret key is
  hidden until this link is clicked, instead of always shown.
- **Expired/locked resend** — while a code is still live, "Resend code" is a
  small text link with a cooldown timer; once it expires or the attempt
  limit is hit, it's replaced by a full-width **"Resend New Code"** button
  (`.resend-btn`), matching the OTP-expired / max-attempts screens exactly.
- **Lockout copy** — standardized to "Maximum attempts reached. Please
  request a new code." across every OTP screen.
- **Invalid-credentials icon** — `login.html`'s icon circle switches to the
  red/error variant (`#loginIcon.error`) when the login fails, matching the
  red shield-alert state in the mockup.

## Notes for the "explain the flow" video (Part 2 of the assignment)

Use this as your talking outline:
- **OTP flow**: button click → `newOtpChallenge()` creates a code +
  expiry timestamp → stored in `localStorage` → `initOtpScreen`
  polls every second to update the countdown → user input compared
  against the stored code → on match, next step's OTP is generated
  and the pending record moves forward.
- **Auth/session flow**: on final MFA success, the pending
  registration is copied into `secureid_users` (this stands in for a
  database write). On login, `secureid_session` stands in for a
  session/JWT: it's created on successful OTP verification, read by
  `dashboard.html` to know who's logged in, and deleted on logout
  (stands in for token invalidation).
