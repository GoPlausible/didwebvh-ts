/**
 * Verification-material checks for DID documents read from a DID log.
 *
 * Malformed material is refused; material this module cannot evaluate is not.
 * A JWK must carry no member the IANA JWK registry classes as Private (DID Core
 * §5.2.1; Controlled Identifiers v1.0 §2.2.3) and must have the members every
 * key of its type requires (`x` for EC and OKP). For the curves known here the
 * key is checked further: EC P-256/P-384/P-521/secp256k1 and OKP Ed25519/Ed448
 * for coordinate size and a point on the curve, OKP X25519/X448 for length
 * only; RSA needs minimal Base64urlUInt values, an odd modulus and 3 ≤ e < n.
 * Key types and curves not known here pass as unsupported, and key strength is
 * not judged. A Multikey (base58btc, multicodec header) of a known multicodec
 * must decode to a key of the right length and, where the curve is available,
 * a valid point. Any other `publicKeyMultibase` needs a registered multibase
 * prefix and a payload; the payload is decoded where a decoder is available
 * here and otherwise not validated.
 */
import { ed448 } from '@noble/curves/ed448.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  base16,
  base32,
  base32hex,
  base32hexnopad,
  base32nopad,
  base36,
  base58,
  base58flickr,
  base64,
  base64nopad,
  base64url,
  base64urlnopad,
} from '@scure/base';

type PointDecoder = { fromBytes(bytes: Uint8Array): unknown };

const EC_CURVES: Record<string, { point: PointDecoder; size: number }> = {
  'P-256': { point: p256.Point, size: 32 },
  'P-384': { point: p384.Point, size: 48 },
  'P-521': { point: p521.Point, size: 66 },
  secp256k1: { point: secp256k1.Point, size: 32 },
};

/** RFC 8037 §2 OKP curves → public key size and, where available, a point decoder. */
const OKP_CURVES: Record<string, { size: number; point?: PointDecoder }> = {
  Ed25519: { size: 32, point: ed25519.Point },
  Ed448: { size: 57, point: ed448.Point },
  X25519: { size: 32 },
  X448: { size: 56 },
};

/**
 * Every parameter the IANA "JSON Web Key Parameters" registry classes as Private
 * (RFC 7517 §8.1.1): `d` (EC, RSA, OKP — RFC 7518 §6.2.2.1, §6.3.2.1; RFC 8037 §2),
 * the RSA private parameters (RFC 7518 §6.3.2), the symmetric key value `k`
 * (RFC 7518 §6.4.1) and the AKP private key `priv` (RFC 9964).
 */
const JWK_PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/** Multicodec → key length and, where available, a point decoder. */
const MULTICODECS = new Map<number, { name: string; length: number; point?: PointDecoder }>([
  [0xed, { name: 'ed25519', length: 32, point: ed25519.Point }],
  [0xec, { name: 'x25519', length: 32 }],
  [0xe7, { name: 'secp256k1', length: 33, point: secp256k1.Point }],
  [0x1200, { name: 'p256', length: 33, point: p256.Point }],
  [0x1201, { name: 'p384', length: 49, point: p384.Point }],
  [0x1202, { name: 'p521', length: 67, point: p521.Point }],
  [0xeb, { name: 'bls12_381-g2', length: 96 }],
]);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Strict, non-empty base64url without padding; null when malformed. */
function base64urlBytes(text: unknown): Uint8Array | null {
  if (typeof text !== 'string' || text.length === 0) {
    return null;
  }
  try {
    return base64urlnopad.decode(text);
  } catch {
    return null;
  }
}

/** Base64urlUInt (RFC 7518 §2): base64url of the minimum number of big-endian octets. */
function base64urlUInt(text: unknown): Uint8Array | null {
  const bytes = base64urlBytes(text);
  return bytes && (bytes.length === 1 || bytes[0] !== 0) ? bytes : null;
}

const toBigInt = (bytes: Uint8Array): bigint => bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);

function onCurve(point: PointDecoder | undefined, bytes: Uint8Array): boolean {
  if (!point) {
    return true;
  }
  try {
    point.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}

/** Why `jwk` is not a well-formed public JWK, or null. */
export function jwkProblem(jwk: unknown): string | null {
  if (!isPlainObject(jwk)) {
    return 'publicKeyJwk must be a JWK object';
  }
  const secret = JWK_PRIVATE_MEMBERS.filter((member) => jwk[member] !== undefined);
  if (secret.length > 0) {
    return `publicKeyJwk must not carry private key members (${secret.join(', ')})`;
  }
  if (typeof jwk.kty !== 'string' || jwk.kty.length === 0) {
    return 'publicKeyJwk.kty is required (RFC 7517 §4.1)';
  }
  switch (jwk.kty) {
    case 'EC': {
      if (typeof jwk.crv !== 'string') {
        return 'publicKeyJwk.crv is required for an EC key (RFC 7518 §6.2.1.1)';
      }
      // RFC 7518 §6.2.1: "crv" and "x" MUST be present for all EC public keys.
      const x = base64urlBytes(jwk.x);
      if (!x) {
        return 'publicKeyJwk.x must be present and base64url for an EC key (RFC 7518 §6.2.1)';
      }
      const spec = EC_CURVES[jwk.crv];
      if (!spec) {
        return null; // a curve not known here: unsupported, not malformed
      }
      const y = base64urlBytes(jwk.y);
      if (!y || x.length !== spec.size || y.length !== spec.size) {
        return `publicKeyJwk x and y must be base64url of ${spec.size} bytes for ${jwk.crv}`;
      }
      const uncompressed = new Uint8Array(1 + 2 * spec.size);
      uncompressed[0] = 0x04;
      uncompressed.set(x, 1);
      uncompressed.set(y, 1 + spec.size);
      return onCurve(spec.point, uncompressed) ? null : `publicKeyJwk is not a point on ${jwk.crv}`;
    }
    case 'OKP': {
      if (typeof jwk.crv !== 'string') {
        return 'publicKeyJwk.crv is required for an OKP key (RFC 8037 §2)';
      }
      // RFC 8037 §2: "x" MUST be present and base64url, whatever the curve.
      const x = base64urlBytes(jwk.x);
      if (!x) {
        return 'publicKeyJwk.x must be present and base64url for an OKP key (RFC 8037 §2)';
      }
      const spec = OKP_CURVES[jwk.crv];
      if (!spec) {
        return null; // a curve not known here: unsupported, not malformed
      }
      if (x.length !== spec.size) {
        return `publicKeyJwk.x must be base64url of ${spec.size} bytes for ${jwk.crv}`;
      }
      return onCurve(spec.point, x) ? null : `publicKeyJwk is not a point on ${jwk.crv}`;
    }
    case 'RSA': {
      const n = base64urlUInt(jwk.n);
      const e = base64urlUInt(jwk.e);
      if (!n || !e) {
        return 'publicKeyJwk n and e must be Base64urlUInt values (minimal octets, RFC 7518 §2)';
      }
      // RFC 8017 §3.1: the modulus is a product of odd primes; 3 <= e <= n - 1, and e is
      // odd because it must be coprime to lambda(n). Key size is policy, not validity.
      if ((n[n.length - 1] & 1) === 0) {
        return 'publicKeyJwk n must be odd (RFC 8017 §3.1)';
      }
      const exponent = toBigInt(e);
      if ((e[e.length - 1] & 1) === 0 || exponent < 3n || exponent >= toBigInt(n)) {
        return 'publicKeyJwk e must be an odd integer from 3 to n - 1 (RFC 8017 §3.1)';
      }
      return null;
    }
    case 'oct':
      // RFC 7518 §6.4.1: a symmetric key's only material is the secret `k`.
      return 'publicKeyJwk must not be a symmetric (oct) key';
    default:
      return null; // a key type not known here: unsupported, not malformed
  }
}

/**
 * Why `value` is not a usable Multikey, or null. Known multicodecs must carry
 * a key of the right length and, where the curve is available, a valid point;
 * unknown multicodecs pass on syntax alone.
 */
export function multikeyProblem(value: unknown): string | null {
  if (typeof value !== 'string' || value[0] !== 'z' || value.length < 2) {
    return 'must be base58btc multibase (z…)';
  }
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(value.slice(1));
  } catch {
    return 'must be base58btc multibase (z…)';
  }
  // Unsigned-varint multicodec: at most five 7-bit groups, terminated by a
  // byte without the continuation bit, minimal, and followed by key bytes.
  let codec = 0;
  let length = 0;
  let terminated = false;
  for (; length < decoded.length && length < 5; length += 1) {
    codec += (decoded[length] & 0x7f) * 2 ** (7 * length);
    if ((decoded[length] & 0x80) === 0) {
      terminated = true;
      length += 1;
      break;
    }
  }
  if (!terminated) {
    return 'multicodec varint does not terminate';
  }
  if (length > 1 && decoded[length - 1] === 0) {
    return 'multicodec varint is not minimal';
  }
  const key = decoded.subarray(length);
  if (key.length === 0) {
    return 'carries no key bytes after the multicodec';
  }
  const spec = MULTICODECS.get(codec);
  if (!spec) {
    return null;
  }
  if (key.length !== spec.length) {
    return `multicodec 0x${codec.toString(16)} needs ${spec.length} key bytes, got ${key.length}`;
  }
  return onCurve(spec.point, key) ? null : `is not a valid ${spec.name} public key`;
}

/**
 * Registered multibase prefixes (multiformats/multibase, multibase.csv) this
 * module decodes. Base16, base32 and base36 are case-insensitive.
 */
const MULTIBASE_DECODERS: Record<string, { name: string; decode: (text: string) => Uint8Array }> = {
  f: { name: 'base16', decode: (t) => base16.decode(t.toUpperCase()) },
  F: { name: 'base16upper', decode: (t) => base16.decode(t.toUpperCase()) },
  b: { name: 'base32', decode: (t) => base32nopad.decode(t.toUpperCase()) },
  B: { name: 'base32upper', decode: (t) => base32nopad.decode(t.toUpperCase()) },
  c: { name: 'base32pad', decode: (t) => base32.decode(t.toUpperCase()) },
  C: { name: 'base32padupper', decode: (t) => base32.decode(t.toUpperCase()) },
  v: { name: 'base32hex', decode: (t) => base32hexnopad.decode(t.toUpperCase()) },
  V: { name: 'base32hexupper', decode: (t) => base32hexnopad.decode(t.toUpperCase()) },
  t: { name: 'base32hexpad', decode: (t) => base32hex.decode(t.toUpperCase()) },
  T: { name: 'base32hexpadupper', decode: (t) => base32hex.decode(t.toUpperCase()) },
  k: { name: 'base36', decode: (t) => base36.decode(t.toLowerCase()) },
  K: { name: 'base36upper', decode: (t) => base36.decode(t.toLowerCase()) },
  z: { name: 'base58btc', decode: (t) => base58.decode(t) },
  Z: { name: 'base58flickr', decode: (t) => base58flickr.decode(t) },
  m: { name: 'base64', decode: (t) => base64nopad.decode(t) },
  M: { name: 'base64pad', decode: (t) => base64.decode(t) },
  u: { name: 'base64url', decode: (t) => base64urlnopad.decode(t) },
  U: { name: 'base64urlpad', decode: (t) => base64url.decode(t) },
};

/** Registered prefixes (experimental or draft) this module cannot decode: a payload is required, not validated. */
const MULTIBASE_UNCHECKED = new Set(['0', '7', '9', 'h', 'R', 'p', '\u{1F680}']);

/**
 * Why `value` is not a multibase-encoded key (DID Core §5.2.1: "a string
 * representation of a MULTIBASE encoded public key"), or null. The bytes are
 * not interpreted; that is the verification method type's concern.
 */
export function multibaseProblem(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0) {
    return 'must be a multibase string';
  }
  const prefix = String.fromCodePoint(value.codePointAt(0) as number);
  const body = value.slice(prefix.length);
  if (body.length === 0) {
    return 'encodes no key bytes';
  }
  const codec = MULTIBASE_DECODERS[prefix];
  if (codec) {
    let bytes: Uint8Array;
    try {
      bytes = codec.decode(body);
    } catch {
      return `is not valid ${codec.name} multibase`;
    }
    return bytes.length > 0 ? null : 'encodes no key bytes';
  }
  return MULTIBASE_UNCHECKED.has(prefix) ? null : `has no registered multibase prefix ('${prefix}')`;
}
