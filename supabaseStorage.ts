import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { ENV } from "./_core/env";

export type StorageObject = {
  key: string;
  url: string;
};

type StorageData = Buffer | Uint8Array | string;

let client: SupabaseClient | null = null;

export function isSupabaseStorageConfigured(): boolean {
  return Boolean(ENV.supabaseUrl && ENV.supabaseServiceRoleKey);
}

export function isSupabaseProductsStorageConfigured(): boolean {
  return isSupabaseStorageConfigured() && Boolean(ENV.supabaseProductsBucket);
}

export function isSupabasePaymentProofsStorageConfigured(): boolean {
  return isSupabaseStorageConfigured() && Boolean(ENV.supabasePaymentProofsBucket);
}

function getSupabaseClient(): SupabaseClient {
  if (!isSupabaseStorageConfigured()) {
    throw new Error(
      "Supabase Storage is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.",
    );
  }

  if (!client) {
    client = createClient(ENV.supabaseUrl, ENV.supabaseServiceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });
  }

  return client;
}

function toUploadBody(data: StorageData): StorageData {
  if (typeof data === "string" || Buffer.isBuffer(data)) return data;
  return new Uint8Array(data);
}

export async function supabaseStoragePut(
  key: string,
  data: StorageData,
  contentType: string,
): Promise<StorageObject> {
  const supabase = getSupabaseClient();
  const { error } = await supabase.storage
    .from(ENV.supabaseProductsBucket)
    .upload(key, toUploadBody(data), {
      cacheControl: "31536000",
      contentType,
      upsert: false,
    });

  if (error) {
    throw new Error(`Supabase Storage upload failed: ${error.message}`);
  }

  const { data: publicUrl } = supabase.storage
    .from(ENV.supabaseProductsBucket)
    .getPublicUrl(key);

  if (!publicUrl.publicUrl) {
    throw new Error("Supabase Storage returned an empty public URL");
  }

  return { key, url: publicUrl.publicUrl };
}

export async function supabasePaymentProofPut(
  key: string,
  data: StorageData,
  contentType: string,
): Promise<StorageObject> {
  const supabase = getSupabaseClient();
  const { error } = await supabase.storage
    .from(ENV.supabasePaymentProofsBucket)
    .upload(key, toUploadBody(data), {
      cacheControl: "3600",
      contentType,
      upsert: false,
    });

  if (error) {
    throw new Error(`Supabase payment-proof upload failed: ${error.message}`);
  }

  // Store the object path in MySQL, never a public URL.
  return {
    key,
    url: key,
  };
}

export async function supabasePaymentProofRemove(key: string): Promise<void> {
  const supabase = getSupabaseClient();
  const { error } = await supabase.storage
    .from(ENV.supabasePaymentProofsBucket)
    .remove([key]);

  if (error) {
    throw new Error(`Supabase payment-proof delete failed: ${error.message}`);
  }
}

export async function supabaseStorageGet(key: string): Promise<StorageObject> {
  const supabase = getSupabaseClient();
  const { data } = supabase.storage
    .from(ENV.supabaseProductsBucket)
    .getPublicUrl(key);

  return { key, url: data.publicUrl };
}

export async function supabaseStorageGetSignedUrl(
  key: string,
  expiresInSeconds = 3600,
): Promise<string> {
  return supabaseStorageGetSignedUrlForBucket(
    ENV.supabaseProductsBucket,
    key,
    expiresInSeconds,
  );
}

export async function supabaseStorageGetPaymentProofSignedUrl(
  key: string,
  expiresInSeconds = 300,
): Promise<string> {
  return supabaseStorageGetSignedUrlForBucket(
    ENV.supabasePaymentProofsBucket,
    key,
    expiresInSeconds,
  );
}

async function supabaseStorageGetSignedUrlForBucket(
  bucket: string,
  key: string,
  expiresInSeconds: number,
): Promise<string> {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase.storage
    .from(bucket)
    .createSignedUrl(key, expiresInSeconds);

  if (error || !data?.signedUrl) {
    throw new Error(
      `Supabase Storage signed URL failed: ${error?.message ?? "empty URL"}`,
    );
  }

  return data.signedUrl;
}
