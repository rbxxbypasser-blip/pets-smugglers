
const crypto = require("crypto");

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");
    if (index < 0) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function createSession(data, secret) {
  const payload = Buffer.from(
    JSON.stringify(data)
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DISCORD_REDIRECT_URI,
    SESSION_SECRET
  } = process.env;

  if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET ||
    !DISCORD_REDIRECT_URI ||
    !SESSION_SECRET ||
    SESSION_SECRET.length < 32
  ) {
    return res.status(500).send(
      "Server OAuth configuration is incomplete."
    );
  }

  const url = new URL(
    req.url,
    "https://example.invalid"
  );

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const issuer = url.searchParams.get("iss");

  const savedState = getCookie(
    req,
    "discord_oauth_state"
  );

  const clearState =
    "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/discord/callback; Max-Age=0";

  if (
    !code ||
    !state ||
    !savedState ||
    state.length !== savedState.length ||
    !crypto.timingSafeEqual(
      Buffer.from(state),
      Buffer.from(savedState)
    ) ||
    (issuer && issuer !== "https://discord.com")
  ) {
    res.setHeader("Set-Cookie", clearState);

    return res.status(400).send(
      "Authorization state validation failed. Please try again."
    );
  }

  try {
    const tokenResponse = await fetch(
      "https://discord.com/api/v10/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: DISCORD_REDIRECT_URI
        })
      }
    );

    if (!tokenResponse.ok) {
      res.setHeader("Set-Cookie", clearState);

      return res.status(400).send(
        "Discord authorization exchange failed. Please try again."
      );
    }

    const tokenData = await tokenResponse.json();

    const userResponse = await fetch(
      "https://discord.com/api/v10/users/@me",
      {
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`
        }
      }
    );

    if (!userResponse.ok) {
      res.setHeader("Set-Cookie", clearState);

      return res.status(400).send(
        "Could not confirm Discord authorization."
      );
    }

    const user = await userResponse.json();

    if (!user.id) {
      res.setHeader("Set-Cookie", clearState);

      return res.status(400).send(
        "Discord account confirmation failed."
      );
    }

    const session = createSession(
      {
        discordConnected: true,
        discordUserId: user.id,
        robloxConnected: false,
        issuedAt: Date.now()
      },
      SESSION_SECRET
    );

    res.setHeader("Set-Cookie", [
      clearState,
      `ps_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
    ]);

    return res.redirect(302, "/");

  } catch (error) {
    console.error("Discord callback failed:", error.message);

    res.setHeader("Set-Cookie", clearState);

    return res.status(500).send(
      "Something went wrong during authorization."
    );
  }
};

