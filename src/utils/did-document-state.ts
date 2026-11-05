/**
 * Structural validation of a DID log entry's `state` as a DID Core document.
 *
 * Resolution verifies the hash chain, timestamps, update authorisation,
 * witnesses and `state.id`; a correctly signed entry can still carry a state
 * that is not a DID document (`verificationMethod: "not-an-array"`). DID
 * Resolution returns the state as the DID document, so every entry's state is
 * checked here: required properties and their types, DID / DID URL / URI
 * syntax (relative DID URLs resolved against the subject), at most one
 * property for a method's key material and each material property
 * well-formed where its format is defined, a JSON-LD
 * `@context` that starts with the DID Core context, references that resolve,
 * and unique ids. Key material is decoded only far enough to check it is a
 * usable public key (see key-material.ts).
 */
import { VERIFICATION_RELATIONSHIPS } from '../constants.js';
import { jwkProblem, multibaseProblem, multikeyProblem } from './key-material.js';

const DID_CORE_CONTEXT = 'https://www.w3.org/ns/did/v1';
const DID_PATTERN = /^did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]$/;
const DID_URL_PATTERN = /^did:[a-z0-9]+:[^\s]+$/;
const RELATIVE_REF = /^[#?/][^\s]*$/;
const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/;
const CAIP10_PATTERN = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;
// DID Core §5.2.1: a verification method's `type` (its cryptographic suite) defines its
// material, and a method MUST NOT carry the same material in more than one property. No
// material property is required of every method: the two types Controlled Identifiers v1.0
// defines make theirs OPTIONAL (Multikey: publicKeyMultibase, §2.2.2; JsonWebKey:
// publicKeyJwk, §2.2.3), and the requirements of other types are left to their own
// specifications, which this module does not implement. These public-key encodings are one
// material; `blockchainAccountId` names an account, not a key.
const PUBLIC_KEY_PROPERTIES = [
  'publicKeyJwk',
  'publicKeyMultibase',
  'publicKeyBase58',
  'publicKeyHex',
  'publicKeyPem',
] as const;
const MATERIAL_PROPERTIES = [...PUBLIC_KEY_PROPERTIES, 'blockchainAccountId'] as const;

export class InvalidDidDocumentState extends Error {}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function isUri(value: string): boolean {
  if (value.length === 0) {
    return false;
  }
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function absoluteId(value: unknown, did: string): string | null {
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  if (RELATIVE_REF.test(value)) {
    return did + value;
  }
  return isUri(value) ? value : null;
}

function materialProblem(vm: Record<string, unknown>): string | null {
  const keys = PUBLIC_KEY_PROPERTIES.filter((name) => vm[name] !== undefined);
  if (keys.length > 1) {
    return `has more than one verification material property (${keys.join(', ')})`;
  }
  for (const name of MATERIAL_PROPERTIES) {
    if (vm[name] !== undefined) {
      const problem = propertyProblem(name, vm[name], vm.type);
      if (problem !== null) {
        return problem;
      }
    }
  }
  return null;
}

function propertyProblem(name: (typeof MATERIAL_PROPERTIES)[number], value: unknown, type: unknown): string | null {
  switch (name) {
    case 'publicKeyJwk':
      return jwkProblem(value);
    case 'publicKeyMultibase': {
      // Controlled Identifiers v1.0 §2.2.2 defines the encoding for `Multikey`; for any other
      // type DID Core asks for a string representation of a multibase-encoded key, so only the
      // multibase syntax is checked and the decoded bytes are left to the type's own specification.
      const problem = type === 'Multikey' ? multikeyProblem(value) : multibaseProblem(value);
      return problem === null ? null : `publicKeyMultibase ${problem}`;
    }
    case 'publicKeyBase58':
      return typeof value === 'string' && BASE58_PATTERN.test(value) ? null : 'publicKeyBase58 must be base58btc';
    case 'publicKeyHex':
      return typeof value === 'string' && /^(0x)?([0-9a-fA-F]{2})+$/.test(value)
        ? null
        : 'publicKeyHex must be hex bytes';
    case 'publicKeyPem':
      return typeof value === 'string' && value.includes('-----BEGIN') ? null : 'publicKeyPem must be PEM text';
    case 'blockchainAccountId':
      return typeof value === 'string' && CAIP10_PATTERN.test(value)
        ? null
        : 'blockchainAccountId must be a CAIP-10 account id';
  }
  return null;
}

function contextProblem(context: unknown): string | null {
  if (context === undefined) {
    return null;
  }
  if (typeof context === 'string') {
    return context === DID_CORE_CONTEXT ? null : `@context must be ${DID_CORE_CONTEXT}`;
  }
  if (!Array.isArray(context) || context.length === 0) {
    return `@context must be ${DID_CORE_CONTEXT} or a non-empty array starting with it`;
  }
  if (context[0] !== DID_CORE_CONTEXT) {
    return `@context[0] must be ${DID_CORE_CONTEXT}`;
  }
  for (let i = 1; i < context.length; i += 1) {
    const item = context[i];
    if (typeof item === 'string' ? !isUri(item) : !isPlainObject(item)) {
      return `@context[${i}] must be a context URI or a context object`;
    }
  }
  return null;
}

function failAt(where: string, detail: string): never {
  throw new InvalidDidDocumentState(`${where} is not a DID document: ${detail}`);
}

/** Throws `InvalidDidDocumentState` unless `state` is a structurally valid DID document for `did`. */
export function assertDidDocumentState(state: unknown, did: string, where: string): void {
  if (!isPlainObject(state)) {
    failAt(where, 'must be a JSON object');
  }
  if (state.id !== did) {
    failAt(where, `id must be ${did}`);
  }
  const context = contextProblem(state['@context']);
  if (context !== null) {
    failAt(where, context);
  }

  if (state.controller !== undefined) {
    const controllers = Array.isArray(state.controller) ? state.controller : [state.controller];
    if (controllers.length === 0 || !controllers.every((c) => typeof c === 'string' && DID_PATTERN.test(c))) {
      failAt(where, 'controller must be a DID or a non-empty array of DIDs');
    }
  }
  if (state.alsoKnownAs !== undefined) {
    if (!Array.isArray(state.alsoKnownAs) || !state.alsoKnownAs.every((a) => typeof a === 'string' && isUri(a))) {
      failAt(where, 'alsoKnownAs must be an array of URIs');
    }
  }

  const seen = new Set<string>();
  const methodIds = new Set<string>();
  const claim = (id: string, place: string) => {
    if (seen.has(id)) {
      failAt(where, `duplicate id '${id}' (${place})`);
    }
    seen.add(id);
  };
  const checkMethod = (vm: unknown, place: string) => {
    if (!isPlainObject(vm)) {
      failAt(where, `${place} must be a verification method object`);
    }
    const id = absoluteId(vm.id, did);
    if (id === null || !DID_URL_PATTERN.test(id)) {
      failAt(where, `${place}.id must be a DID URL`);
    }
    if (typeof vm.type !== 'string' || vm.type.length === 0) {
      failAt(where, `${place}.type must be a string`);
    }
    if (typeof vm.controller !== 'string' || !DID_PATTERN.test(vm.controller)) {
      failAt(where, `${place}.controller must be a DID`);
    }
    const material = materialProblem(vm);
    if (material !== null) {
      failAt(where, `${place} ${material}`);
    }
    claim(id, place);
    methodIds.add(id);
  };

  if (state.verificationMethod !== undefined) {
    if (!Array.isArray(state.verificationMethod)) {
      failAt(where, 'verificationMethod must be an array');
    }
    for (const [i, vm] of state.verificationMethod.entries()) {
      checkMethod(vm, `verificationMethod[${i}]`);
    }
  }
  // DID Core §5.3: a relationship entry is a method embedded there or a reference to a method
  // defined anywhere in the document (including one embedded under another relationship), so
  // every method is collected first and references are checked in a second pass.
  const references: Array<{ place: string; id: string }> = [];
  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const value = state[relationship];
    if (value === undefined) {
      continue;
    }
    if (!Array.isArray(value)) {
      failAt(where, `${relationship} must be an array`);
    }
    value.forEach((entry, i) => {
      if (typeof entry === 'string') {
        const absolute = absoluteId(entry, did);
        if (absolute === null || !DID_URL_PATTERN.test(absolute)) {
          failAt(where, `${relationship}[${i}] must be a DID URL`);
        }
        references.push({ place: `${relationship}[${i}]`, id: absolute });
        return;
      }
      checkMethod(entry, `${relationship}[${i}]`);
    });
  }
  for (const { place, id } of references) {
    if (id.startsWith(`${did}#`) && !methodIds.has(id)) {
      failAt(where, `${place} references undefined verification method '${id}'`);
    }
  }
  if (state.service !== undefined) {
    if (!Array.isArray(state.service)) {
      failAt(where, 'service must be an array');
    }
    state.service.forEach((entry, i) => {
      if (!isPlainObject(entry)) {
        failAt(where, `service[${i}] must be a service object`);
      }
      const id = absoluteId(entry.id, did);
      if (id === null) {
        failAt(where, `service[${i}].id must be a URI or a relative DID URL`);
      }
      claim(id, `service[${i}]`);
      const typeOk =
        (typeof entry.type === 'string' && entry.type.length > 0) ||
        (Array.isArray(entry.type) &&
          entry.type.length > 0 &&
          entry.type.every((t) => typeof t === 'string' && t.length > 0));
      if (!typeOk) {
        failAt(where, `service[${i}].type must be a string or a non-empty array of strings`);
      }
      const endpointOk = (value: unknown) => (typeof value === 'string' && isUri(value)) || isPlainObject(value);
      const endpoints = Array.isArray(entry.serviceEndpoint) ? entry.serviceEndpoint : [entry.serviceEndpoint];
      if (entry.serviceEndpoint === undefined || endpoints.length === 0 || !endpoints.every(endpointOk)) {
        failAt(where, `service[${i}].serviceEndpoint must be a URI, a map, or a non-empty set of them`);
      }
    });
  }
}
