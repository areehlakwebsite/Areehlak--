import crypto from "node:crypto";
import { ENV } from "./_core/env";

const PAYMOB_BASE_URL = "https://accept.paymob.com/api";

type BillingData = { first_name: string; last_name: string; phone_number: string; city: string; state: string; street: string; country: string; email: string; building: string; floor: string; apartment: string; postal_code: string; extra_description: string };

function requireConfig() {
  const missing = [
    !ENV.paymobApiKey && "PAYMOB_API_KEY",
    !ENV.paymobIntegrationId && "PAYMOB_INTEGRATION_ID",
    !ENV.paymobIframeId && "PAYMOB_IFRAME_ID",
    !ENV.paymobHmacSecret && "PAYMOB_HMAC_SECRET",
  ].filter(Boolean);
  if (missing.length) throw new Error("بوابة الدفع غير مهيأة بعد. أضف PAYMOB_API_KEY وPAYMOB_INTEGRATION_ID وPAYMOB_IFRAME_ID وPAYMOB_HMAC_SECRET إلى إعدادات المشروع.");
}

async function post(path: string, body: unknown) {
  const response = await fetch(`${PAYMOB_BASE_URL}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Paymob request failed (${response.status})`);
  return data;
}

export async function createPaymobPayment(input: { orderId: number; merchantOrderId?: string; amountCents: number; customerName: string; phone: string; governorate: string; city: string; address: string }) {
  requireConfig();
  const auth = await post("/auth/tokens", { api_key: ENV.paymobApiKey });
  const paymobOrder = await post("/ecommerce/orders", { auth_token: auth.token, delivery_needed: false, amount_cents: input.amountCents, currency: "EGP", merchant_order_id: input.merchantOrderId || String(input.orderId), items: [] });
  const nameParts = input.customerName.trim().split(/\s+/);
  const billing: BillingData = { first_name: nameParts[0] || "AreehLak", last_name: nameParts.slice(1).join(" ") || "Customer", phone_number: input.phone, city: input.city, state: input.governorate, street: input.address, country: "EG", email: "customer@areehlak.local", building: "NA", floor: "NA", apartment: "NA", postal_code: "NA", extra_description: `AreehLak order ${input.merchantOrderId || input.orderId}` };
  const paymentKey = await post("/acceptance/payment_keys", { auth_token: auth.token, amount_cents: input.amountCents, expiration: 3600, order_id: paymobOrder.id, billing_data: billing, currency: "EGP", integration_id: Number(ENV.paymobIntegrationId) });
  return { paymentUrl: `https://accept.paymob.com/api/acceptance/iframes/${ENV.paymobIframeId}?payment_token=${encodeURIComponent(paymentKey.token)}`, paymobOrderId: String(paymobOrder.id) };
}

const HMAC_FIELDS = ["amount_cents", "created_at", "currency", "error_occured", "has_parent_transaction", "id", "integration_id", "is_3d_secure", "is_auth", "is_capture", "is_refunded", "is_standalone_payment", "is_voided", "order", "owner", "pending", "source_data.pan", "source_data.sub_type", "source_data.type", "success"] as const;
function getPath(obj: any, path: string) { return path.split(".").reduce((value, key) => value?.[key], obj); }
export function verifyPaymobHmac(payload: any, receivedHmac: string) {
  if (!ENV.paymobHmacSecret || !receivedHmac) return false;
  const raw = HMAC_FIELDS.map(field => String(getPath(payload, field) ?? "")).join("");
  const calculated = crypto.createHmac("sha512", ENV.paymobHmacSecret).update(raw).digest("hex");
  return calculated.length === receivedHmac.length && crypto.timingSafeEqual(Buffer.from(calculated), Buffer.from(receivedHmac));
}

export function paymobConfigured() { return Boolean(ENV.paymobApiKey && ENV.paymobIntegrationId && ENV.paymobIframeId && ENV.paymobHmacSecret); }
