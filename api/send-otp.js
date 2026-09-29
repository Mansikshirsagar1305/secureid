// api/send-otp.js
// ------------------------------------------------------------
// Vercel automatically turns any file under /api into a serverless
// function at /api/<filename>. This is what makes email "real":
// the browser calls fetch("/api/send-otp"), which runs THIS code
// on Vercel's server (never in the user's browser), where it's
// safe to hold a secret API key.
//
// Setup:
//   1. Create a free account at https://resend.com
//   2. Grab an API key (Dashboard -> API Keys)
//   3. In your Vercel project: Settings -> Environment Variables
//        RESEND_API_KEY = re_your_key_here
//   4. (Optional) verify your own domain in Resend and set
//        RESEND_FROM = "SecureID <noreply@yourdomain.com>"
//      Until you do, the default resend.dev test sender is used,
//      which is fine for development/demo purposes.
//   5. Redeploy. sendOtpEmail() in js/app.js will now succeed and
//      every OTP screen switches from "demo mode" to real delivery
//      automatically — no other code changes needed.
// ------------------------------------------------------------

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const { email, code } = req.body || {};
  if (!email || !code) {
    res.status(400).json({ error: "email and code are required" });
    return;
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    // Not configured yet — the front end treats any non-OK response
    // as "fall back to demo mode", so this is a safe, quiet failure.
    res.status(500).json({ error: "RESEND_API_KEY is not set" });
    return;
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: process.env.RESEND_FROM || "SecureID <onboarding@resend.dev>",
        to: [email],
        subject: "Your SecureID verification code",
        html: `
          <div style="font-family: sans-serif; max-width: 420px; margin: auto;">
            <h2 style="color:#2554e0;">SecureID</h2>
            <p>Your verification code is:</p>
            <p style="font-size: 32px; font-weight: 700; letter-spacing: 6px; color:#101828;">${code}</p>
            <p style="color:#667085; font-size: 13px;">
              This code expires in 3 minutes. If you didn't request this, you can safely ignore this email.
            </p>
          </div>
        `
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error("Resend API error:", errText);
      res.status(502).json({ error: "Failed to send email" });
      return;
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error("send-otp error:", err);
    res.status(500).json({ error: "Unexpected error" });
  }
};
