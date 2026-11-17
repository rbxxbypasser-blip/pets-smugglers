
const crypto = require("crypto");

module.exports = (req, res) => {
  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send("OAuth configuration missing");
  }

  const state = crypto.randomBytes(32).toString("hex");

  res.setHeader("Set-Cookie", [
    `discord_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord/callback; Max-Age=600`
  ]);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "identify",
    state: state
  });

  res.redirect(
    302,
    "https://discord.com/oauth2/authorize?" + params.toString()
  );
};
  
