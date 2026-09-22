// Strict canonical base64url decoding for JWS verification.
//
// Background: jose's base64url decoder (like Node's Buffer decoder) is
// lenient — several different strings can decode to the same bytes when the
// final quantum has unused trailing bits (e.g. "_w", "_x", "_y", "_z" all
// decode to 0xFF). A non-canonical JWS compact serialization therefore still
// passes jose.compactVerify, which breaks anything that compares, caches, or
// blocklists the *token string* (the bytes verify, the string doesn't match).
//
// RFC 7515 requires base64url *without padding* in the compact serialization,
// and canonical encoding (unused bits zero). Verifiers must reject anything
// else before checking the signature.
import * as jose from "jose";

const B64URL_ALPHABET = /^[A-Za-z0-9_-]+$/;

/**
 * Decode base64url, rejecting anything that is not the canonical encoding:
 * non-empty, alphabet-only, no padding, and re-encodes byte-for-byte to the
 * original string. Throws on any violation.
 */
export function decodeBase64UrlStrict(input: string): Uint8Array {
  if (typeof input !== "string" || input.length === 0) {
    throw new Error("not canonical base64url: empty input");
  }
  if (!B64URL_ALPHABET.test(input)) {
    throw new Error("not canonical base64url: illegal character or padding");
  }
  const bytes = jose.base64url.decode(input);
  if (jose.base64url.encode(bytes) !== input) {
    throw new Error(
      "not canonical base64url: non-canonical encoding (unused bits set)"
    );
  }
  return bytes;
}

/**
 * Validate every part of a JWS compact serialization (<h>.<p>.<s>).
 * Throws if the shape is wrong or any part is non-canonical base64url.
 */
export function assertCanonicalJws(jws: string): void {
  const parts = (jws || "").split(".");
  if (parts.length !== 3) {
    throw new Error("malformed JWS: expected 3 dot-separated parts");
  }
  for (const part of parts) {
    decodeBase64UrlStrict(part);
  }
}
