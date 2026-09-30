# AreehLak — GitHub / Node.js deployment

## Install and run
```bash
pnpm install --frozen-lockfile
pnpm run check
pnpm run build
pnpm start
```

Set these server-side environment variables in the hosting dashboard:

```env
DATABASE_URL=
JWT_SECRET=
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
SUPABASE_STORAGE_BUCKET_PRODUCTS=book-images
SUPABASE_STORAGE_BUCKET_PAYMENT_PROOFS=payment-proofs
PAYMOB_API_KEY=
PAYMOB_INTEGRATION_ID=
PAYMOB_IFRAME_ID=
PAYMOB_HMAC_SECRET=
WHATSAPP_ACCESS_TOKEN=
WHATSAPP_PHONE_NUMBER_ID=
NODE_ENV=production
PORT=3000
```

`SUPABASE_SERVICE_ROLE_KEY` must stay server-side and must never be exposed through frontend variables. This package intentionally excludes Google verification, `sitemap.xml`, and `robots.txt` files, as requested. It also excludes tests, reports, `node_modules`, `dist`, and `.env` secrets.
