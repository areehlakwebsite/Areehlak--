import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import cookieParser from "cookie-parser";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { ensureAdminAccount } from "../localAuth";
import { getCodeOrderById, getOrderById, updateCodeOrderPaymob, updateOrderPaymob } from "../db";
import { verifyPaymobHmac } from "../paymob";

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => { const server = net.createServer(); server.listen(port, () => server.close(() => resolve(true))); server.on("error", () => resolve(false)); });
}
async function findAvailablePort(startPort = 3000) { for (let port = startPort; port < startPort + 20; port++) if (await isPortAvailable(port)) return port; throw new Error(`No available port found starting from ${startPort}`); }

async function startServer() {
  const app = express();
  const server = createServer(app);
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));
  app.use(cookieParser());
  app.post("/api/paymob/webhook", async (req, res) => {
    try {
      const payload = req.body as any;
      const hmac = String(req.query.hmac || payload?.hmac || "");
      if (!verifyPaymobHmac(payload, hmac)) return res.status(401).json({ ok: false, error: "Invalid HMAC" });
      const source = payload?.obj ?? payload;
      const merchantOrderId = String(source?.order?.merchant_order_id || source?.merchant_order_id || "");
      const isCodeOrder = merchantOrderId.startsWith("code-");
      const localOrderId = Number(isCodeOrder ? merchantOrderId.slice(5) : merchantOrderId || 0);
      const order = !isCodeOrder && localOrderId ? await getOrderById(localOrderId) : undefined;
      const codeOrder = isCodeOrder && localOrderId ? await getCodeOrderById(localOrderId) : undefined;
      if (!order && !codeOrder) return res.status(404).json({ ok: false, error: "Order not found" });
      if (Number(source?.amount_cents) !== (order?.totalAmount || codeOrder?.totalAmount || 0) * 100) return res.status(400).json({ ok: false, error: "Amount mismatch" });
      const success = source?.success === true && source?.pending !== true && source?.is_refunded !== true && source?.is_void !== true;
      if (codeOrder) await updateCodeOrderPaymob(codeOrder.id, { paymentTransactionId: String(source?.id || ""), paymentStatus: success ? "pending" : "failed" });
      else if (order) await updateOrderPaymob(order.id, { paymobTransactionId: String(source?.id || ""), paymentStatus: success ? "paid" : "failed", status: success ? "confirmed" : "pending" });
      return res.json({ ok: true });
    } catch (error) {
      console.error("[Paymob webhook]", error);
      return res.status(500).json({ ok: false });
    }
  });
  app.use("/api/trpc", createExpressMiddleware({ router: appRouter, createContext }));
  if (process.env.NODE_ENV === "development") await setupVite(app, server); else serveStatic(app);
  await ensureAdminAccount();
  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);
  if (port !== preferredPort) console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  server.listen(port, () => console.log(`Server running on http://localhost:${port}/`));
}
startServer().catch(console.error);
