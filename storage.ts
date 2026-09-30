import { ENV } from "./_core/env";
import {
  isSupabaseProductsStorageConfigured,
  isSupabasePaymentProofsStorageConfigured,
  supabaseStorageGet,
  supabaseStorageGetPaymentProofSignedUrl,
  supabaseStorageGetSignedUrl,
  supabasePaymentProofPut,
  supabasePaymentProofRemove,
  supabaseStoragePut,
} from "./supabaseStorage";

function normalizeKey(relKey: string): string {
  return relKey.replace(/^\/+/, "");
}

function appendHashSuffix(relKey: string): string {
  const hash = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  const lastDot = relKey.lastIndexOf(".");
  if (lastDot === -1) return `${relKey}_${hash}`;
  return `${relKey.slice(0, lastDot)}_${hash}${relKey.slice(lastDot)}`;
}

function isProductImage(key: string): boolean {
  return key.startsWith("products/");
}

function isPaymentProof(key: string): boolean {
  return key.startsWith("payment-proofs/");
}

function unsupportedStoragePath(key: string): Error {
  return new Error(`Unsupported Supabase Storage path: ${key}`);
}

export async function storagePut(
  relKey: string,
  data: Buffer | Uint8Array | string,
  contentType = "application/octet-stream",
): Promise<{ key: string; url: string }> {
  const key = appendHashSuffix(normalizeKey(relKey));

  if (isProductImage(key)) {
    if (!isSupabaseProductsStorageConfigured()) {
      throw new Error("Supabase book-images storage is not configured");
    }
    return supabaseStoragePut(key, data, contentType);
  }

  if (isPaymentProof(key)) {
    if (!isSupabasePaymentProofsStorageConfigured()) {
      throw new Error("Supabase payment-proofs storage is not configured");
    }
    return supabasePaymentProofPut(key, data, contentType);
  }

  throw unsupportedStoragePath(key);
}

export async function storageGet(relKey: string): Promise<{ key: string; url: string }> {
  const key = normalizeKey(relKey);
  if (isProductImage(key)) {
    if (!isSupabaseProductsStorageConfigured()) {
      throw new Error("Supabase book-images storage is not configured");
    }
    return supabaseStorageGet(key);
  }
  if (isPaymentProof(key)) {
    if (!isSupabasePaymentProofsStorageConfigured()) {
      throw new Error("Supabase payment-proofs storage is not configured");
    }
    return { key, url: key };
  }
  throw unsupportedStoragePath(key);
}

export async function storageGetSignedUrl(relKey: string): Promise<string> {
  const key = normalizeKey(relKey);
  if (isProductImage(key)) {
    if (!isSupabaseProductsStorageConfigured()) {
      throw new Error("Supabase book-images storage is not configured");
    }
    return supabaseStorageGetSignedUrl(key);
  }
  if (isPaymentProof(key)) {
    if (!isSupabasePaymentProofsStorageConfigured()) {
      throw new Error("Supabase payment-proofs storage is not configured");
    }
    return supabaseStorageGetPaymentProofSignedUrl(key);
  }
  throw unsupportedStoragePath(key);
}

export async function resolveStorageReference(reference: string): Promise<string> {
  const raw = reference.startsWith("supabase://")
    ? reference.slice("supabase://".length).replace(`${ENV.supabasePaymentProofsBucket}/`, "")
    : reference;
  const key = raw.startsWith("payment-proofs/") ? raw : `payment-proofs/${raw}`;

  if (!isPaymentProof(key) || !isSupabasePaymentProofsStorageConfigured()) {
    throw new Error("Invalid Supabase payment-proof reference");
  }

  return supabaseStorageGetPaymentProofSignedUrl(key, 300);
}

export async function deleteStorageReference(reference: string): Promise<void> {
  const raw = reference.startsWith("supabase://")
    ? reference.slice("supabase://".length).replace(`${ENV.supabasePaymentProofsBucket}/`, "")
    : reference;
  const key = raw.startsWith("payment-proofs/") ? raw : `payment-proofs/${raw}`;

  if (!isPaymentProof(key)) return;
  if (!isSupabasePaymentProofsStorageConfigured()) {
    throw new Error("Supabase payment-proofs storage is not configured");
  }

  await supabasePaymentProofRemove(key);
}
