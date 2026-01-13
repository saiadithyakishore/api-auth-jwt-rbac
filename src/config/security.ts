import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { Application } from "express";

export function setupSecurity(app: Application) {
  // 🔐 Headers de segurança
  app.use(helmet());

  // 🌍 CORS (ajuste depois para produção)
  app.use(
    cors({
      origin: "*",
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  );

  // 🚫 Rate limit global (proteção básica)
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // 100 requests por IP
    message: {
      success: false,
      message: "Muitas requisições, tente novamente mais tarde",
    },
  });

  app.use(limiter);
}
