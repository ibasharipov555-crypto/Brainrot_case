import Fastify from "fastify";
import cors from "@fastify/cors";
import { createHmac, timingSafeEqual } from "node:crypto";

const app = Fastify({ logger: true });

const botToken = process.env.TELEGRAM_BOT_TOKEN;
const adminTelegramId = process.env.ADMIN_TELEGRAM_ID;

if (!botToken || !adminTelegramId) {
  throw new Error("Telegram environment variables are missing");
}

await app.register(cors, { origin: true });

app.get("/", async () => ({
  name: "Brainrot Case API",
  status: "online"
}));

app.get("/health", async () => ({
  ok: true
}));

function verifyTelegramInitData(initData: string): URLSearchParams | null {
  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
    return null;
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = createHmac("sha256", "WebAppData")
    .update(botToken!)
    .digest();

  const calculatedHash = createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest();

  const received = Buffer.from(receivedHash, "hex");

  if (
    received.length !== calculatedHash.length ||
    !timingSafeEqual(received, calculatedHash)
  ) {
    return null;
  }

  const authDate = Number(params.get("auth_date"));
  const telegramUser = params.get("user");

  if (
    !Number.isFinite(authDate) ||
    Math.abs(Date.now() / 1000 - authDate) > 300 ||
    !telegramUser
  ) {
    return null;
  }

  return params;
}

app.get("/admin/check", async (request, reply) => {
  const initData = request.headers["x-telegram-init-data"];

  if (typeof initData !== "string") {
    return reply.code(401).send({ error: "Telegram authentication required" });
  }

  const params = verifyTelegramInitData(initData);

  if (!params) {
    return reply.code(401).send({ error: "Invalid or expired Telegram session" });
  }

  let user: { id?: number };

  try {
    user = JSON.parse(params.get("user") || "{}");
  } catch {
    return reply.code(401).send({ error: "Invalid Telegram user data" });
  }

  if (String(user.id) !== adminTelegramId) {
    return reply.code(403).send({ error: "Admin access denied" });
  }

  return {
    ok: true,
    admin: true,
    message: "Telegram admin authentication successful"
  };
});

const port = Number(process.env.PORT || 3000);

await app.listen({
  port,
  host: "0.0.0.0"
});
  
