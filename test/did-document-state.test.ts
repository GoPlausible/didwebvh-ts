import { ed448 } from '@noble/curves/ed448.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { describe, expect, test } from 'vitest';
import type { DataIntegrityProofTemplate, DIDLog } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { deriveHash } from '../src/utils/crypto.js';
import { assertDidDocumentState } from '../src/utils/did-document-state.js';
import { encodeBase58Btc } from '../src/utils/multiformats.js';
import {
  createTestDIDDocument,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

const DID = 'did:webvh:QmScid:example.com';
const KEY = 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V';

const validState = () => ({
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: DID,
  verificationMethod: [{ id: `${DID}#key-1`, type: 'Multikey', controller: DID, publicKeyMultibase: KEY }],
  authentication: [`${DID}#key-1`],
  service: [{ id: '#files', type: 'LinkedDomains', serviceEndpoint: 'https://example.com/' }],
});

const rejects = (state: unknown, fragment: string) =>
  expect(() => assertDidDocumentState(state, DID, 'state'), fragment).toThrow(fragment);

describe('assertDidDocumentState', () => {
  test('accepts a conformant state', () => {
    expect(() => assertDidDocumentState(validState(), DID, 'state')).not.toThrow();
  });

  test('refuses states whose structure violates DID Core', () => {
    rejects('not an object', 'must be a JSON object');
    rejects({ ...validState(), id: 'did:webvh:QmOther:example.com' }, 'id must be');
    rejects({ ...validState(), '@context': [] }, '@context must be');
    rejects({ ...validState(), '@context': 42 }, '@context must be');
    rejects(
      { ...validState(), '@context': ['https://w3id.org/security/multikey/v1', 'https://www.w3.org/ns/did/v1'] },
      '@context[0] must be'
    );
    rejects({ ...validState(), verificationMethod: 'not-an-array' }, 'verificationMethod must be an array');
    rejects({ ...validState(), authentication: [42] }, 'authentication[0] must be a verification method object');
    // DID Core §5.2.1 makes verification material OPTIONAL; its type decides what it needs
    expect(() =>
      assertDidDocumentState(
        {
          ...validState(),
          verificationMethod: [
            ...validState().verificationMethod,
            { id: `${DID}#k`, type: 'Multikey', controller: DID },
          ],
        },
        DID,
        'state'
      )
    ).not.toThrow();
    rejects(
      {
        ...validState(),
        verificationMethod: [
          { id: `${DID}#k`, type: 'Multikey', controller: DID, publicKeyMultibase: KEY, publicKeyJwk: {} },
        ],
      },
      'more than one verification material property'
    );
    rejects(
      {
        ...validState(),
        verificationMethod: [{ id: 'bare-id', type: 'Multikey', controller: DID, publicKeyMultibase: KEY }],
      },
      'id must be a DID URL'
    );
    rejects({ ...validState(), service: [{ id: '#s', type: 'X', serviceEndpoint: 42 }] }, 'serviceEndpoint must be');
    rejects({ ...validState(), authentication: [`${DID}#missing`] }, 'references undefined verification method');
    rejects({ ...validState(), controller: 'not a did' }, 'controller must be a DID');
    rejects({ ...validState(), alsoKnownAs: 'https://example.com' }, 'alsoKnownAs must be an array');
  });

  test('resolves references in any property order and refuses dangling ones (DID Core §5.3)', () => {
    const embedded = { id: `${DID}#key-2`, type: 'Multikey', controller: DID, publicKeyMultibase: KEY };
    // authentication references a method embedded later, under assertionMethod
    expect(() =>
      assertDidDocumentState(
        { ...validState(), authentication: [`${DID}#key-2`], assertionMethod: [embedded] },
        DID,
        'state'
      )
    ).not.toThrow();
    // a service id is not a verification method
    rejects({ ...validState(), authentication: [`${DID}#files`] }, 'references undefined verification method');
    // an embedded method is validated like any other
    rejects(
      {
        ...validState(),
        assertionMethod: [
          { id: `${DID}#key-3`, type: 'Multikey', controller: DID, publicKeyMultibase: KEY, publicKeyBase58: 'abc' },
        ],
      },
      'more than one verification material property'
    );
  });
});

describe('verification material must be a usable public key', () => {
  const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
  const multibase = (bytes: number[]) => `z${encodeBase58Btc(Uint8Array.from(bytes))}`;
  const state = (material: Record<string, unknown>, type = 'JsonWebKey') => ({
    id: DID,
    verificationMethod: [{ id: `${DID}#k`, type, controller: DID, ...material }],
  });
  const fails = (material: Record<string, unknown>, fragment: string, type?: string) =>
    expect(() => assertDidDocumentState(state(material, type), DID, 'state'), fragment).toThrow(fragment);

  test('accepts usable JWKs and refuses unusable or private ones', () => {
    const ec = p256.getPublicKey(p256.utils.randomSecretKey(), false);
    expect(() =>
      assertDidDocumentState(
        state({ publicKeyJwk: { kty: 'EC', crv: 'P-256', x: b64u(ec.slice(1, 33)), y: b64u(ec.slice(33)) } }),
        DID,
        'state'
      )
    ).not.toThrow();
    const okp = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
    expect(() =>
      assertDidDocumentState(state({ publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(okp) } }), DID, 'state')
    ).not.toThrow();
    fails({ publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(okp), d: b64u(okp) } }, 'must not carry private key');
    fails({ publicKeyJwk: { kty: 'EC' } }, 'crv is required for an EC key');
    fails({ publicKeyJwk: { kty: 'RSA' } }, 'n and e must be Base64urlUInt');
    fails({ publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'not-base64url!' } }, 'x must be present and base64url');
    fails(
      { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(okp.subarray(1)) } },
      'x must be base64url of 32 bytes'
    );
    fails(
      { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32).fill(0xff)) } },
      'not a point on Ed25519'
    );
    fails({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256)), e: 'AQ' } }, 'n and e must be Base64urlUInt');
    fails({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x9b)), e: 'AQ' } }, 'odd integer from 3');
  });

  test('refuses every private JWK member (RFC 7517 §8.1.1 private information class)', () => {
    const rsa = { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x9b)), e: 'AQAB' };
    expect(() => assertDidDocumentState(state({ publicKeyJwk: rsa }), DID, 'state')).not.toThrow();
    for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      fails({ publicKeyJwk: { ...rsa, [member]: 'AQAB' } }, `private key members (${member})`);
    }
    fails({ publicKeyJwk: { ...rsa, oth: [{ r: 'AQAB', d: 'AQAB', t: 'AQAB' }] } }, 'private key members (oth)');
    fails({ publicKeyJwk: { kty: 'oct', k: 'c2VjcmV0' } }, 'private key members (k)');
    fails({ publicKeyJwk: { kty: 'oct' } }, 'must not be a symmetric (oct) key');
    // RFC 9964: the AKP private key, registered Private in the IANA JWK registry
    fails({ publicKeyJwk: { kty: 'AKP', alg: 'ML-DSA-44', pub: 'AQAB', priv: 'AQAB' } }, 'private key members (priv)');
  });

  test('checks RSA values as Base64urlUInt and RFC 8017, not key-size policy', () => {
    const odd = (length: number, first: number) => {
      const n = new Uint8Array(length).fill(0x9b);
      n[0] = first;
      return b64u(n);
    };
    // a first octet below 0x80 is still minimal; 1024 bits is weak, not malformed
    for (const n of [odd(256, 0x7f), odd(128, 0xc5)]) {
      expect(() =>
        assertDidDocumentState(state({ publicKeyJwk: { kty: 'RSA', n, e: 'AQAB' } }), DID, 'state')
      ).not.toThrow();
    }
    fails({ publicKeyJwk: { kty: 'RSA', n: `AA${odd(256, 0x9b)}`, e: 'AQAB' } }, 'Base64urlUInt');
    fails({ publicKeyJwk: { kty: 'RSA', n: odd(256, 0x9b), e: 'AAEAAQ' } }, 'Base64urlUInt');
    fails({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x9a)), e: 'AQAB' } }, 'n must be odd');
    fails({ publicKeyJwk: { kty: 'RSA', n: odd(256, 0x9b), e: 'AQAA' } }, 'odd integer from 3');
    fails({ publicKeyJwk: { kty: 'RSA', n: 'BQ', e: 'Bw' } }, 'odd integer from 3');
  });

  test('accepts other standardised curves and leaves unknown key types unjudged', () => {
    const ed = ed448.getPublicKey(ed448.utils.randomSecretKey());
    for (const jwk of [
      { kty: 'OKP', crv: 'Ed448', x: b64u(ed) },
      { kty: 'OKP', crv: 'X448', x: b64u(new Uint8Array(56).fill(7)) },
      { kty: 'OKP', crv: 'X25519', x: b64u(new Uint8Array(32).fill(7)) },
      { kty: 'EC', crv: 'brainpoolP256r1', x: 'AQAB', y: 'AQAB' },
      { kty: 'AKP', alg: 'ML-DSA-44', pub: 'AQAB' },
    ]) {
      expect(
        () => assertDidDocumentState(state({ publicKeyJwk: jwk }), DID, 'state'),
        jwk.crv ?? jwk.kty
      ).not.toThrow();
    }
    fails({ publicKeyJwk: { kty: 'OKP', crv: 'Ed448', x: b64u(ed.subarray(1)) } }, 'x must be base64url of 57 bytes');
    fails(
      { publicKeyJwk: { kty: 'OKP', crv: 'Ed448', x: b64u(new Uint8Array(57).fill(0xff)) } },
      'not a point on Ed448'
    );
    fails({ publicKeyJwk: { kty: 'OKP', x: b64u(ed) } }, 'crv is required for an OKP key');
    fails({ publicKeyJwk: { crv: 'Ed25519', x: 'AQAB' } }, 'kty is required');
  });

  test('checks the members every EC and OKP key needs, whatever the curve', () => {
    // an unknown curve with its common members present passes as unsupported
    expect(() =>
      assertDidDocumentState(state({ publicKeyJwk: { kty: 'OKP', crv: 'unknown-curve', x: 'AQAB' } }), DID, 'state')
    ).not.toThrow();
    // RFC 8037 §2: "x" MUST be present and base64url for every OKP key
    fails({ publicKeyJwk: { kty: 'OKP', crv: 'unknown-curve' } }, 'x must be present and base64url for an OKP key');
    fails(
      { publicKeyJwk: { kty: 'OKP', crv: 'unknown-curve', x: '!!' } },
      'x must be present and base64url for an OKP key'
    );
    // RFC 7518 §6.2.1: "crv" and "x" MUST be present for all EC public keys
    fails({ publicKeyJwk: { kty: 'EC', crv: 'brainpoolP256r1' } }, 'x must be present and base64url for an EC key');
    fails(
      { publicKeyJwk: { kty: 'EC', crv: 'brainpoolP256r1', x: '!!' } },
      'x must be present and base64url for an EC key'
    );
  });

  test('accepts a canonical Multikey and refuses non-canonical or unusable ones', () => {
    const key = Array.from(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));
    expect(() =>
      assertDidDocumentState(state({ publicKeyMultibase: multibase([0xed, 0x01, ...key]) }, 'Multikey'), DID, 'state')
    ).not.toThrow();
    const m = 'Multikey';
    fails(
      { publicKeyMultibase: multibase([0xe7, 0x01, 0x02, ...new Array(32).fill(0xff)]) },
      'not a valid secp256k1',
      m
    );
    fails({ publicKeyMultibase: multibase([0xed, 0x81, 0x80, 0x80, 0x80, ...key]) }, 'varint does not terminate', m);
    fails({ publicKeyMultibase: multibase([0xed, 0x81, 0x00, ...key]) }, 'varint is not minimal', m);
    fails({ publicKeyMultibase: multibase([0x80, 0x26]) }, 'no key bytes', m);
    fails({ publicKeyMultibase: 'm-not-base58btc' }, 'must be base58btc multibase', m);
  });

  test('applies the Multikey encoding only to Multikey methods (DID Core §5.2.1)', () => {
    const key = Buffer.from(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));
    const raw = key.toString('base64').replace(/=+$/, '');
    // another suite's multibase encoding (no multicodec header) is not a Multikey's to judge
    expect(() =>
      assertDidDocumentState(state({ publicKeyMultibase: `m${raw}` }, 'Ed25519VerificationKey2018'), DID, 'state')
    ).not.toThrow();
    fails({ publicKeyMultibase: `m${raw}` }, 'must be base58btc multibase', 'Multikey');
    fails({ publicKeyMultibase: 42 }, 'must be a multibase string', 'Ed25519VerificationKey2018');
    // material in an extension property is left to its own definition
    expect(() =>
      assertDidDocumentState(
        state({ ethereumAddress: '0x89a932207c485f85226d86f7cd486a89a24fcc12' }, 'EcdsaSecp256k1RecoveryMethod2020'),
        DID,
        'state'
      )
    ).not.toThrow();
  });

  test('checks the multibase syntax of other types without interpreting the key', () => {
    const key = Buffer.from(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));
    const t = 'Ed25519VerificationKey2018';
    for (const value of [
      `u${key.toString('base64url')}`,
      `M${key.toString('base64')}`,
      `f${key.toString('hex')}`,
      `F${key.toString('hex').toUpperCase()}`,
      `z${encodeBase58Btc(key)}`,
      'pbabab-dabab', // proquint: registered, not decoded here
    ]) {
      expect(() => assertDidDocumentState(state({ publicKeyMultibase: value }, t), DID, 'state'), value).not.toThrow();
    }
    fails({ publicKeyMultibase: '!!' }, "no registered multibase prefix ('!')", t);
    fails({ publicKeyMultibase: `1${encodeBase58Btc(key)}` }, "no registered multibase prefix ('1')", t);
    fails({ publicKeyMultibase: `m${key.toString('base64')}` }, 'not valid base64 multibase', t);
    fails({ publicKeyMultibase: 'fabc' }, 'not valid base16 multibase', t);
    fails({ publicKeyMultibase: 'z0OIl' }, 'not valid base58btc multibase', t);
    fails({ publicKeyMultibase: 'u' }, 'encodes no key bytes', t);
    // a registered prefix without a decoder here still needs a payload
    fails({ publicKeyMultibase: 'p' }, 'encodes no key bytes', t);
    fails({ publicKeyMultibase: '0' }, 'encodes no key bytes', t);
  });
});

describe('resolution validates every signed state', () => {
  // A log author does not have to use this library: re-chain and re-sign a tampered
  // entry the way another writer could, so only document validation can refuse it.
  async function resolveWithState(mutate: (state: Record<string, unknown>) => unknown) {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const signer = createTestSigner(authKey);
    const { log } = await createDID({
      address: 'example.com',
      signer,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier,
    });
    const { log: updated } = await updateDID({ log, signer, updateKeys: [authKey.publicKeyMultibase!], verifier });
    const forged: DIDLog = JSON.parse(JSON.stringify(updated));
    forged[1].state = mutate(forged[1].state as Record<string, unknown>) as DIDLog[number]['state'];
    const { proof: _proof, ...unsigned } = forged[1];
    forged[1].versionId = `2-${await deriveHash({ ...unsigned, versionId: forged[0].versionId })}`;
    const { proof: _stale, ...toSign } = forged[1];
    const template: DataIntegrityProofTemplate = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: signer.getVerificationMethodId(),
      created: forged[1].versionTime,
      proofPurpose: 'assertionMethod',
    };
    const signed = await signer.sign({ document: toSign, proof: template });
    forged[1].proof = [{ ...template, proofValue: signed.proofValue }];
    return resolveDIDFromLog(forged, { verifier });
  }

  test('a re-signed entry that keeps a valid document still resolves', async () => {
    const resolved = await resolveWithState((state) => ({ ...state, alsoKnownAs: ['https://example.com/alias'] }));
    expect(resolved.didResolutionMetadata.error).toBeUndefined();
  });

  test('a correctly signed state that is not a DID document is refused', async () => {
    const resolved = await resolveWithState((state) => ({
      '@context': 42,
      id: state.id,
      verificationMethod: 'not-an-array',
      authentication: [42],
    }));
    expect(resolved.didDocument).toBeNull();
    expect(resolved.didResolutionMetadata.error).toBe('invalidDid');
    expect(resolved.didResolutionMetadata.message).toMatch(/version '2' state is not a DID document/);
  });
});
