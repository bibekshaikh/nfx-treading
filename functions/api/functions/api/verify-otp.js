
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function makeToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.OTP_STORE) {
      return json({ error: "OTP storage is not configured." }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid request." }, 400);
    }

    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !/^\d{6}$/.test(code)
    ) {
      return json({ error: "Invalid email or verification code." }, 400);
    }

    const emailHash = await sha256(email);
    const otpKey = `otp:${emailHash}`;
    const stored = await env.OTP_STORE.get(otpKey);

    if (!stored) {
      return json({
        error: "OTP expired or not found. Please request a new code."
      }, 400);
    }

    let record;
    try {
      record = JSON.parse(stored);
    } catch {
      await env.OTP_STORE.delete(otpKey);
      return json({ error: "Invalid OTP record. Please request a new code." }, 400);
    }

    if (!Number.isInteger(record.attempts) || record.attempts >= 5) {
      await env.OTP_STORE.delete(otpKey);
      return json({ error: "Too many attempts. Please request a new OTP." }, 429);
    }

    const submittedHash = await sha256(`${email}:${code}`);

    if (submittedHash !== record.hash) {
      record.attempts += 1;

      if (record.attempts >= 5) {
        await env.OTP_STORE.delete(otpKey);
        return json({
          error: "Too many incorrect attempts. Please request a new OTP."
        }, 429);
      }

      await env.OTP_STORE.put(
        otpKey,
        JSON.stringify(record),
        { expirationTtl: 300 }
      );

      return json({
        error: "Incorrect OTP. Please try again.",
        attemptsRemaining: 5 - record.attempts
      }, 400);
    }

    // Consume the OTP so it cannot be reused.
    await env.OTP_STORE.delete(otpKey);

    // Create a short-lived, one-time registration verification ticket.
    const verificationToken = makeToken();
    const tokenHash = await sha256(verificationToken);

    await env.OTP_STORE.put(
      `verified:${tokenHash}`,
      JSON.stringify({ email, used: false }),
      { expirationTtl: 600 }
    );

    return json({
      success: true,
      message: "Email verified successfully.",
      verificationToken
    });

  } catch {
    return json({ error: "Server error. Please try again later." }, 500);
  }
}
