
const crypto = require("crypto");

module.exports = (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    return res.status(500).json({
      error: "Session configuration missing"
    });
  }

  const cookieHeader = req.headers.cookie || "";

  const sessionCookie = cookieHeader
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith("ps_session="));

  if (!sessionCookie) {
    return res.status(200).json({
      discordConnected: false,
      robloxConnected: false
    });
  }

  try {
    const token = decodeURIComponent(
      sessionCookie.substring("ps_session=".length)
    );

    const parts = token.split(".");

    if (parts.length !== 2) {
      throw new Error("Invalid session");
    }

    const [payload, signature] = parts;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      throw new Error("Invalid signature");
    }

    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    const age = Date.now() - session.issuedAt;

    if (
      age < 0 ||
      age > 24 * 60 * 60 * 1000
    ) {
      throw new Error("Session expired");
    }

    return res.status(200).json({
      discordConnected:
        session.discordConnected === true,

      robloxConnected:
        session.robloxConnected === true
    });

  } catch {
    return res.status(200).json({
      discordConnected: false,
      robloxConnected: false
    });
  }
};
  
