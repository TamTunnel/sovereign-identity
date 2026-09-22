// Regression test for strict canonical base64url enforcement
// (run: npm run test:strict-b64).
//
// jose's base64url decoder is lenient: several strings can decode to the same
// bytes when the final quantum has unused trailing bits (e.g. "_w", "_x",
// "_y", "_z" all decode to 0xFF), and jose.compactVerify ACCEPTS such a
// non-canonical JWS. The strict helpers below must reject it.
import * as jose from "jose";
import {
  decodeBase64UrlStrict,
  assertCanonicalJws,
} from "./strict_base64url.js";

let failures = 0;

function expectAccept(input: string, label: string) {
  try {
    decodeBase64UrlStrict(input);
    console.log(`  PASS (accepted): ${label}`);
  } catch (err: any) {
    failures++;
    console.error(`  FAIL (should have been accepted): ${label}`);
    console.error(`       ${err.message}`);
  }
}

function expectReject(input: string, label: string) {
  try {
    decodeBase64UrlStrict(input);
    failures++;
    console.error(`  FAIL (should have been rejected): ${label}`);
  } catch {
    console.log(`  PASS (rejected): ${label}`);
  }
}

console.log("--- strict base64url: decode ---");

// Canonical encodings of real byte strings must pass.
expectAccept(jose.base64url.encode(new Uint8Array([0xff])), "canonical 0xFF");
expectAccept(
  jose.base64url.encode(new TextEncoder().encode('{"alg":"EdDSA"}')),
  "canonical JSON header"
);

// Non-canonical same-bytes variants must fail.
expectReject("_x", "non-canonical 0xFF ('_x')");
expectReject("_y", "non-canonical 0xFF ('_y')");
expectReject("_z", "non-canonical 0xFF ('_z')");

// Padding and out-of-alphabet characters must fail.
expectReject("_w=", "padded base64url");
expectReject("ab+cd", "base64 '+' in base64url");
expectReject("ab/cd", "base64 '/' in base64url");
expectReject("ab cd", "whitespace");
expectReject("ab\ncd", "newline");

// Empty input must fail.
expectReject("", "empty string");

console.log("--- strict base64url: JWS shape ---");

function expectJwsReject(jws: string, label: string) {
  try {
    assertCanonicalJws(jws);
    failures++;
    console.error(`  FAIL (should have been rejected): ${label}`);
  } catch {
    console.log(`  PASS (rejected): ${label}`);
  }
}

expectJwsReject("a.b", "two parts");
expectJwsReject("a.b.c.d", "four parts");
expectJwsReject("", "empty JWS");

console.log("--- strict base64url: end-to-end vs jose leniency ---");

// Sign a real JWS, then build a same-bytes non-canonical variant of it.
const { publicKey, privateKey } = await jose.generateKeyPair("EdDSA");
const jws = await new jose.CompactSign(new TextEncoder().encode('{"t":1}'))
  .setProtectedHeader({ alg: "EdDSA" })
  .sign(privateKey);
const [h, p, s] = jws.split(".");

const sigBytes = jose.base64url.decode(s);
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
let variant: string | null = null;
for (const c of alphabet) {
  const v = s.slice(0, -1) + c;
  if (v === s) continue;
  try {
    const d = jose.base64url.decode(v);
    if (d.length === sigBytes.length && d.every((b, i) => b === sigBytes[i])) {
      variant = v;
      break;
    }
  } catch {
    /* ignore undecodable candidates */
  }
}

if (!variant) {
  failures++;
  console.error("  FAIL: could not construct a non-canonical variant");
} else {
  const nonCanonicalJws = `${h}.${p}.${variant}`;

  // Document the underlying leniency: jose verifies it...
  let joseAccepted = false;
  try {
    await jose.compactVerify(nonCanonicalJws, publicKey);
    joseAccepted = true;
  } catch {
    /* expected only if jose ever becomes strict */
  }
  console.log(
    `  INFO: jose.compactVerify ${joseAccepted ? "ACCEPTS" : "rejects"} the non-canonical JWS`
  );

  // ...but the strict gate must reject it.
  try {
    assertCanonicalJws(nonCanonicalJws);
    failures++;
    console.error("  FAIL (should have been rejected): non-canonical JWS variant");
  } catch {
    console.log("  PASS (rejected): non-canonical JWS variant");
  }

  // The canonical original must still pass the gate.
  try {
    assertCanonicalJws(jws);
    console.log("  PASS (accepted): canonical JWS");
  } catch (err: any) {
    failures++;
    console.error("  FAIL (should have been accepted): canonical JWS");
    console.error(`       ${err.message}`);
  }
}

if (failures > 0) {
  console.error(`\n💥 strict base64url test FAILED (${failures} case(s))`);
  process.exit(1);
}
console.log("\n🏆 strict base64url test PASSED");
