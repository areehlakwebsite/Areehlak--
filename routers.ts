import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { approveManualPayment, createCodeOrder, createLocalUser, createManualPayment, createOrder, createProduct, createSubscriptionCode, deleteManualPayment, deleteOrder, deleteProduct, deleteSubscriptionCode, deleteUserAccount, getCategories, listDeliveryRates, upsertDeliveryRate, getCodeOrderById, getOrderById, getProductById, getUserByPhone, getUserById, listCodeOrders, listManualPayments, listOrders, listOrdersForUser, listProducts, listSubscriptionCodes, listUsers, rejectManualPayment, reopenManualPayment, updateCodeOrderDeliveryStatus, updateUserDelivery, updateUserProfile, updateCodeOrderPayment, updateOrderPaymob, updateOrderStatus, updateProduct, updateUserSecrets, setUserBlocked } from "./db";
import { createPaymobPayment } from "./paymob";
import { clearSession, createSession, hashSecret, isEgyptianPhone, normalizePhone, PIN_LIMITS, verifySecret } from "./localAuth";
import { storagePut } from "./storage";

const productInput = z.object({ title: z.string().min(2), slug: z.string().min(2), teacher: z.string().optional(), publisher: z.string().optional(), subject: z.string().min(2), stage: z.string().min(2), grade: z.string().optional(), type: z.string().min(2), category: z.string().min(2), price: z.number().int().nonnegative(), originalPrice: z.number().int().nonnegative().optional(), imageUrl: z.string().min(1, "يرجى رفع صورة الكتاب"), description: z.string().min(2), pages: z.number().int().positive().optional(), stock: z.number().int().nonnegative(), isVisible: z.boolean().default(true), isAvailable: z.boolean().default(true), isPreorder: z.boolean().default(false), isFeatured: z.boolean().default(false), isBestseller: z.boolean().default(false) });
const phoneInput = z.string().transform(normalizePhone).refine(isEgyptianPhone, "أدخل رقم هاتف مصري صحيح");
const passwordInput = z.string().min(8, "كلمة المرور يجب أن تكون 8 أحرف على الأقل");
const pinInput = z.string().regex(/^\d{4}$/, "رمز الأمان يجب أن يكون 4 أرقام");
const adminOnlyProcedure = adminProcedure;
const publicUser = (user: typeof import("../drizzle/schema").users.$inferSelect | null) => user ? { id: user.id, phone: user.phone, name: user.name, email: user.email, role: user.role, deliveryGovernorate: user.deliveryGovernorate, deliveryCity: user.deliveryCity, deliveryAddress: user.deliveryAddress, deliveryNotes: user.deliveryNotes } : null;

export const appRouter = router({
  auth: router({
    me: publicProcedure.query(opts => publicUser(opts.ctx.user)),
    updateDelivery: protectedProcedure.input(z.object({ deliveryGovernorate: z.string().trim().min(2, "المحافظة مطلوبة"), deliveryCity: z.string().trim().min(2, "المدينة مطلوبة"), deliveryAddress: z.string().trim().min(5, "العنوان مطلوب"), deliveryNotes: z.string().trim().max(500).optional() })).mutation(async ({ input, ctx }) => { await updateUserDelivery(ctx.user.id, input); const updated = await getUserByPhone(ctx.user.phone); return publicUser(updated || ctx.user); }),
    updateProfile: protectedProcedure.input(z.object({ name: z.string().trim().min(2, "الاسم مطلوب").max(120, "الاسم طويل جدًا"), phone: phoneInput })).mutation(async ({ input, ctx }) => { const existing = await getUserByPhone(input.phone); if (existing && existing.id !== ctx.user.id) throw new TRPCError({ code: "CONFLICT", message: "رقم الهاتف مسجل بالفعل لحساب آخر" }); await updateUserProfile(ctx.user.id, input); const updated = await getUserByPhone(input.phone); return publicUser(updated || { ...ctx.user, ...input }); }),
    register: publicProcedure.input(z.object({ phone: phoneInput, password: passwordInput, confirmPassword: z.string(), pin: pinInput, confirmPin: z.string(), name: z.string().trim().min(2, "الاسم مطلوب ويجب أن يكون حرفين على الأقل") })).mutation(async ({ input, ctx }) => {
      if (input.password !== input.confirmPassword) throw new TRPCError({ code: "BAD_REQUEST", message: "كلمتا المرور غير متطابقتين" });
      if (input.pin !== input.confirmPin) throw new TRPCError({ code: "BAD_REQUEST", message: "رمزا الأمان غير متطابقين" });
      const existingUser = await getUserByPhone(input.phone); if (existingUser?.isBlocked) throw new TRPCError({ code: "FORBIDDEN", message: "تم حظر هذا الرقم ولا يمكن إنشاء حساب به" }); if (existingUser) throw new TRPCError({ code: "CONFLICT", message: "رقم الهاتف مسجل بالفعل" });
      const result = await createLocalUser({ phone: input.phone, passwordHash: await hashSecret(input.password), securityPinHash: await hashSecret(input.pin), name: input.name });
      await createSession(Number(result[0].insertId), ctx.res);
      return { success: true };
    }),
    login: publicProcedure.input(z.object({ phone: phoneInput, password: z.string().min(1) })).mutation(async ({ input, ctx }) => {
      const user = await getUserByPhone(input.phone);
      if (!user || user.isBlocked) throw new TRPCError({ code: "FORBIDDEN", message: "تم حظر هذا الحساب ولا يمكن تسجيل الدخول" }); if (!(await verifySecret(input.password, user.passwordHash))) throw new TRPCError({ code: "UNAUTHORIZED", message: "رقم الهاتف أو كلمة المرور غير صحيحة" });
      await updateUserSecrets(user.id, { lastSignedIn: new Date() });
      await createSession(user.id, ctx.res);
      return { success: true, role: user.role };
    }),
    forgotPassword: publicProcedure.input(z.object({ phone: phoneInput, pin: pinInput })).mutation(async ({ input }) => {
      const user = await getUserByPhone(input.phone);
      if (!user) throw new TRPCError({ code: "NOT_FOUND", message: "لا يوجد حساب بهذا الرقم" });
      if (user.pinLockedUntil && user.pinLockedUntil > new Date()) throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "تم إيقاف المحاولات مؤقتًا، حاول لاحقًا" });
      const valid = await verifySecret(input.pin, user.securityPinHash);
      if (!valid) { const attempts = user.pinAttempts + 1; await updateUserSecrets(user.id, { pinAttempts: attempts, pinLockedUntil: attempts >= PIN_LIMITS.maxAttempts ? new Date(Date.now() + PIN_LIMITS.lockMinutes * 60000) : null }); throw new TRPCError({ code: "UNAUTHORIZED", message: "رمز الأمان غير صحيح" }); }
      await updateUserSecrets(user.id, { pinAttempts: 0, pinLockedUntil: null });
      return { verified: true };
    }),
    resetPassword: publicProcedure.input(z.object({ phone: phoneInput, pin: pinInput, password: passwordInput, confirmPassword: z.string() })).mutation(async ({ input }) => {
      if (input.password !== input.confirmPassword) throw new TRPCError({ code: "BAD_REQUEST", message: "كلمتا المرور غير متطابقتين" });
      const user = await getUserByPhone(input.phone);
      if (!user || user.pinLockedUntil && user.pinLockedUntil > new Date() || !user || !(await verifySecret(input.pin, user.securityPinHash))) throw new TRPCError({ code: "UNAUTHORIZED", message: "بيانات التحقق غير صحيحة" });
      await updateUserSecrets(user.id, { passwordHash: await hashSecret(input.password), pinAttempts: 0, pinLockedUntil: null });
      return { success: true };
    }),
    logout: publicProcedure.mutation(({ ctx }) => clearSession(ctx.req, ctx.res).then(() => ({ success: true }))),
  }),
  categories: router({ list: publicProcedure.query(() => getCategories()) }),
  deliveryRates: router({ list: publicProcedure.query(() => listDeliveryRates()), adminList: adminOnlyProcedure.query(() => listDeliveryRates()), update: adminOnlyProcedure.input(z.object({ governorate: z.string().trim().min(2), shippingCost: z.number().int().nonnegative().max(100000), extraPerItemCost: z.number().int().nonnegative().max(100000) })).mutation(({ input }) => upsertDeliveryRate(input.governorate, input.shippingCost, input.extraPerItemCost)) }),
  products: router({
    list: publicProcedure.input(z.object({ search: z.string().optional(), stage: z.string().optional(), type: z.string().optional(), subject: z.string().optional(), teacher: z.string().optional(), limit: z.number().optional() }).optional()).query(({ input }) => listProducts(input)),
    adminList: adminOnlyProcedure.input(z.object({ limit: z.number().optional() }).optional()).query(({ input }) => listProducts({ ...input, includeHidden: true })),
    get: publicProcedure.input(z.object({ id: z.number().int().positive() })).query(({ input }) => getProductById(input.id)),
    uploadImage: adminOnlyProcedure.input(z.object({ filename: z.string().min(1), contentType: z.string().min(1), data: z.string().min(20) })).mutation(async ({ input }) => { const base64 = input.data.replace(/^data:[^;]+;base64,/, ""); return storagePut(`products/${input.filename.replace(/[^a-zA-Z0-9._-]/g, "-")}`, Buffer.from(base64, "base64"), input.contentType); }),
    create: adminOnlyProcedure.input(productInput).mutation(({ input }) => createProduct(input)),
    update: adminOnlyProcedure.input(z.object({ id: z.number().int().positive(), data: productInput.partial() })).mutation(({ input }) => updateProduct(input.id, input.data)),
    remove: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ input }) => deleteProduct(input.id)),
  }),
  orders: router({
    create: protectedProcedure.input(z.object({ customerName: z.string().min(2), phone: phoneInput, governorate: z.string().min(2), city: z.string().min(2), address: z.string().min(5), notes: z.string().optional(), items: z.array(z.object({ productId: z.number().int().positive(), quantity: z.number().int().positive(), unitPrice: z.number().int().nonnegative().optional(), specialty: z.string().trim().max(80).optional() })).min(1) })).mutation(({ input, ctx }) => createOrder({ ...input, userId: ctx.user.id })),
    createPayment: protectedProcedure.input(z.object({ customerName: z.string().min(2), phone: phoneInput, governorate: z.string().min(2), city: z.string().min(2), address: z.string().min(5), notes: z.string().optional(), items: z.array(z.object({ productId: z.number().int().positive(), quantity: z.number().int().positive(), specialty: z.string().trim().max(80).optional() })).min(1) })).mutation(async ({ input, ctx }) => { const order = await createOrder({ ...input, userId: ctx.user.id }); const payment = await createPaymobPayment({ orderId: order.orderId, amountCents: order.totalAmount * 100, customerName: input.customerName, phone: input.phone, governorate: input.governorate, city: input.city, address: input.address }); await updateOrderPaymob(order.orderId, { paymobOrderId: payment.paymobOrderId }); return { orderId: order.orderId, paymentUrl: payment.paymentUrl, totalAmount: order.totalAmount }; }),
    createManualOrder: protectedProcedure.input(z.object({ customerName: z.string().min(2), phone: phoneInput, governorate: z.string().min(2), city: z.string().min(2), address: z.string().min(5), notes: z.string().optional(), items: z.array(z.object({ productId: z.number().int().positive(), quantity: z.number().int().positive(), specialty: z.string().trim().max(80).optional() })).min(1) })).mutation(({ input, ctx }) => createOrder({ ...input, userId: ctx.user.id, paymentMethod: "manual_wallet" })),
    retryPayment: protectedProcedure.input(z.object({ id: z.number().int().positive() })).mutation(async ({ input, ctx }) => { const order = await getOrderById(input.id); if (!order || order.userId !== ctx.user.id) throw new TRPCError({ code: "NOT_FOUND" }); if (order.paymentStatus === "paid") throw new TRPCError({ code: "BAD_REQUEST", message: "هذا الطلب مدفوع بالفعل" }); const payment = await createPaymobPayment({ orderId: order.id, amountCents: order.totalAmount * 100, customerName: order.customerName, phone: order.phone, governorate: order.governorate, city: order.city, address: order.address }); await updateOrderPaymob(order.id, { paymobOrderId: payment.paymobOrderId, paymentStatus: "pending", status: "pending" }); return { paymentUrl: payment.paymentUrl }; }),
    mine: protectedProcedure.query(({ ctx }) => listOrdersForUser(ctx.user.id)),
    getMine: protectedProcedure.input(z.object({ id: z.number().int().positive() })).query(async ({ input, ctx }) => { const order = await getOrderById(input.id); if (!order || order.userId !== ctx.user.id) throw new TRPCError({ code: "NOT_FOUND" }); return order; }),
    adminList: adminOnlyProcedure.query(() => listOrders()),
    updateStatus: adminOnlyProcedure.input(z.object({ id: z.number().int().positive(), status: z.enum(["pending", "processing", "shipped", "delivered", "cancelled"]) })).mutation(({ input }) => updateOrderStatus(input.id, input.status)),
    remove: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ input }) => deleteOrder(input.id)),
  }),
  manualPayments: router({
    uploadProof: protectedProcedure.input(z.object({ filename: z.string().min(1), contentType: z.string().regex(/^image\/(jpeg|png|webp|gif)$/i, "يجب رفع صورة بصيغة صحيحة"), data: z.string().min(100) })).mutation(async ({ input, ctx }) => { const base64 = input.data.replace(/^data:[^;]+;base64,/, ""); const buffer = Buffer.from(base64, "base64"); if (buffer.length > 5 * 1024 * 1024) throw new TRPCError({ code: "BAD_REQUEST", message: "حجم صورة إثبات التحويل يجب ألا يتجاوز 5 ميجابايت" }); const safeName = input.filename.replace(/[^a-zA-Z0-9._-]/g, "-"); return storagePut(`payment-proofs/${ctx.user.id}/${Date.now()}-${safeName}`, buffer, input.contentType); }),
    create: protectedProcedure.input(z.object({ orderId: z.number().int().positive().optional(), codeOrderId: z.number().int().positive().optional(), paymentMethod: z.enum(["vodafone_cash", "orange_cash", "we_pay", "etisalat_cash"]), walletPhone: phoneInput, transferScreenshot: z.string().refine(value => value.startsWith("payment-proofs/") || value.startsWith("supabase://payment-proofs/"), "صورة إثبات التحويل غير صالحة") }).refine(input => Boolean(input.orderId || input.codeOrderId), "رقم الطلب مطلوب")).mutation(({ input, ctx }) => { const rawPath = input.transferScreenshot.startsWith("supabase://") ? input.transferScreenshot.replace("supabase://payment-proofs/", "") : input.transferScreenshot; const path = rawPath.startsWith("payment-proofs/") ? rawPath : `payment-proofs/${rawPath}`; if (path.startsWith("payment-proofs/") && !path.startsWith(`payment-proofs/${ctx.user.id}/`)) throw new TRPCError({ code: "FORBIDDEN", message: "مرجع إثبات التحويل غير صالح لهذا المستخدم" }); return createManualPayment({ ...input, userId: ctx.user.id }); }),
    mine: protectedProcedure.query(({ ctx }) => listManualPayments(ctx.user.id)),
    adminList: adminOnlyProcedure.input(z.object({ paymentNumber: z.string().trim().max(80).optional() }).optional()).query(({ input }) => listManualPayments(undefined, input?.paymentNumber || undefined)),
    remove: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ input, ctx }) => deleteManualPayment(input.id, ctx.user.id)),
    approve: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ input, ctx }) => approveManualPayment(input.id, ctx.user.id)),
    reject: adminOnlyProcedure.input(z.object({ id: z.number().int().positive(), reason: z.string().trim().min(2, "اكتب سبب الرفض").max(500) })).mutation(({ input, ctx }) => rejectManualPayment(input.id, ctx.user.id, input.reason)),
    reopen: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ input, ctx }) => reopenManualPayment(input.id, ctx.user.id)),
  }),
  users: router({
    adminList: adminOnlyProcedure.input(z.object({ phone: z.string().trim().max(30).optional() }).optional()).query(({ input }) => listUsers(input?.phone)),
    remove: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(async ({ input, ctx }) => { const target = await getUserById(input.id); if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "المستخدم غير موجود" }); if (input.id === ctx.user.id || target.role === "admin") throw new TRPCError({ code: "FORBIDDEN", message: "لا يمكن حذف حساب مدير" }); return deleteUserAccount(input.id); }),
    block: adminOnlyProcedure.input(z.object({ id: z.number().int().positive(), isBlocked: z.boolean() })).mutation(async ({ input, ctx }) => { const target = await getUserById(input.id); if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "المستخدم غير موجود" }); if (input.id === ctx.user.id || target.role === "admin") throw new TRPCError({ code: "FORBIDDEN", message: "لا يمكن حظر حساب مدير" }); return setUserBlocked(input.id, input.isBlocked); }),
  }),
  codes: router({
    list: publicProcedure.query(() => listSubscriptionCodes(false)),
    mine: protectedProcedure.query(({ ctx }) => listCodeOrders(ctx.user.id)),
    purchase: protectedProcedure.input(z.object({ codeId: z.number().int().positive(), deliveryMethod: z.literal("home_delivery"), governorate: z.string().min(2, "المحافظة مطلوبة"), city: z.string().min(2, "المدينة مطلوبة"), address: z.string().min(5, "العنوان مطلوب"), notes: z.string().optional() })).mutation(({ input, ctx }) => createCodeOrder({ ...input, userId: ctx.user.id, customerName: ctx.user.name || "مستخدم Areehlak", phone: ctx.user.phone })),
    getMine: protectedProcedure.input(z.object({ id: z.number().int().positive() })).query(async ({ input, ctx }) => { const order = await getCodeOrderById(input.id); if (!order || order.userId !== ctx.user.id) throw new TRPCError({ code: "NOT_FOUND" }); return order; }),
    adminList: adminOnlyProcedure.query(() => listSubscriptionCodes(true)),
    adminOrders: adminOnlyProcedure.query(() => listCodeOrders()),
    create: adminOnlyProcedure.input(z.object({ teacherName: z.string().trim().min(2), planType: z.enum(["monthly", "three_months"]), price: z.number().int().nonnegative(), imageUrl: z.string().optional() })).mutation(({ input }) => createSubscriptionCode({ ...input, code: `internal-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`, imageUrl: input.imageUrl || null, isSold: false })),
    remove: adminOnlyProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ input }) => deleteSubscriptionCode(input.id)),
    markPaid: adminOnlyProcedure.input(z.object({ id: z.number().int().positive(), paymentStatus: z.enum(["pending", "paid", "failed", "cancelled"]), paymentTransactionId: z.string().optional() })).mutation(({ input }) => updateCodeOrderPayment(input.id, input.paymentStatus, input.paymentTransactionId)),
    updateDeliveryStatus: adminOnlyProcedure.input(z.object({ id: z.number().int().positive(), deliveryStatus: z.enum(["pending", "processing", "shipped", "delivered", "cancelled"]) })).mutation(({ input }) => updateCodeOrderDeliveryStatus(input.id, input.deliveryStatus)),
  }),
});
export type AppRouter = typeof appRouter;
