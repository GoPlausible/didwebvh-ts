/// <reference lib="dom" />
import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalizeStrict } from './canonicalize.js';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from './multiformats.js';

const encoder = new TextEncoder();

function arrayBufferToHex(buffer: ArrayBufferLike | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createHash(data: string): Promise<Uint8Array> {
  return sha256(encoder.encode(data));
}

export async function createHashHex(data: string): Promise<string> {
  const hash = await createHash(data);
  const view = new Uint8Array(hash.buffer);
  return arrayBufferToHex(view);
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
};

// Cache for deriveHash operations to avoid redundant computation. Keys are
// whole log entries chosen by DID controllers, so the cache is bounded by
// entry count and total key size and evicts the least recently used entry.
export const HASH_CACHE_MAX_ENTRIES = 256;
export const HASH_CACHE_MAX_BYTES = 2 * 1024 * 1024;
const hashCache = new Map<string, string>();
let hashCacheBytes = 0;

export function hashCacheStats(): { entries: number; bytes: number } {
  return { entries: hashCache.size, bytes: hashCacheBytes };
}

function cacheHash(key: string, hash: string): void {
  // An entry larger than a quarter of the budget would evict most of the cache.
  if (key.length > HASH_CACHE_MAX_BYTES / 4 || hashCache.has(key)) {
    return;
  }
  hashCache.set(key, hash);
  hashCacheBytes += key.length;
  while (hashCache.size > HASH_CACHE_MAX_ENTRIES || hashCacheBytes > HASH_CACHE_MAX_BYTES) {
    const oldest = hashCache.keys().next();
    if (oldest.done) {
      break;
    }
    hashCache.delete(oldest.value);
    hashCacheBytes -= oldest.value.length;
  }
}

// Input must be strict JSON-compatible and must not contain explicit undefined values.
export async function deriveHash(input: unknown): Promise<string> {
  let cacheKey: string | undefined;

  try {
    cacheKey = JSON.stringify(input);
    const cached = hashCache.get(cacheKey);
    if (cached) {
      // Refresh recency so eviction is least-recently-used.
      hashCache.delete(cacheKey);
      hashCache.set(cacheKey, cached);
      return cached;
    }
  } catch {
    cacheKey = undefined;
  }

  const data = canonicalizeStrict(input);
  const hash = await createHash(data);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  const result = encodeBase58Btc(multihash);

  if (cacheKey !== undefined) {
    cacheHash(cacheKey, result);
  }

  return result;
}

export const deriveNextKeyHash = async (input: string): Promise<string> => {
  const hash = await createHash(input);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  return encodeBase58Btc(multihash);
};
