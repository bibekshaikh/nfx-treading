
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

export async function onRequestPost({ request, env }) {
  try {
    if (!env.OTP_STORE) {
      return json({ error: "OTP storage is not configured." }, 500);
    }

    const { EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID,
      EMAILJS_PUBLIC_KEY, EMAILJS_PRIVATE_KEY } = env;

    if (!EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID ||
        !EMAILJS_PUBLIC_KEY || !EMAILJS_PRIVATE_KEY) {
      return json({ error: "Email service is not configured." }, 500);
    }

    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();

    if (email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return json({ error: "Please enter a valid email address." }, 400);
    }

    const emailHash = await sha256(email);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await sha256(ip);

    const emailKey = `cooldown:email:${emailHash}`;
    const ipKey = `cooldown:ip:${ipHash}`;

    if (await env.OTP_STORE.get(emailKey)) {
      return json({ error: "Please wait 60 seconds before requesting another OTP." }, 429);
    }

    if (await env.OTP_STORE.get(ipKey)) {
      return json({ error: "Too many requests. Please wait 60 seconds." }, 429);
    }

    const random = new Uint32Array(1);
    crypto.getRandomValues(random);
    const otp = String(random[0] % 1000000).padStart(6, "0");
    const otpHash = await sha256(`${email}:${otp}`);

    await env.OTP_STORE.put(emailKey, "1", { expirationTtl: 60 });
    await env.OTP_STORE.put(ipKey, "1", { expirationTtl: 60 });

    const emailResponse = await fetch(
      "https://api.emailjs.com/api/v1.0/email/send",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service_id: EMAILJS_SERVICE_ID,
          template_id: EMAILJS_TEMPLATE_ID,
          user_id: EMAILJS_PUBLIC_KEY,
          accessToken: EMAILJS_PRIVATE_KEY,
          template_params: {
            to_email: email,
            passcode: otp
          }
        })
      }
    );

    if (!emailResponse.ok) {
      await env.OTP_STORE.delete(emailKey);
      await env.OTP_STORE.delete(ipKey);
      return json({ error: "Could not send OTP. Please try again later." }, 502);
    }

    await env.OTP_STORE.put(
      `otp:${emailHash}`,
      JSON.stringify({ hash: otpHash, attempts: 0 }),
      { expirationTtl: 300 }
    );

    return json({
      success: true,
      message: "OTP sent. It is valid for 5 minutes."
    });

  } catch (error) {
    return json({ error: "Server error. Please try again later." }, 500);
  }
}
