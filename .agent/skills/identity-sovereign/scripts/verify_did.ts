import * as jose from "jose";
import * as fs from "fs";
import * as path from "path";
import bs58 from "bs58";
import { fileURLToPath } from "url";
import { assertCanonicalJws } from "./strict_base64url.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Derive the Ed25519 public key (base64url "x") implied by a did:key.
 * For did:key, the DID *is* the key: z-base58(multicodec(0xed01) || x).
 * Throws if the DID is not a well-formed Ed25519 did:key.
 */
function didKeyToJwkX(did: string): string {
  const m = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)$/.exec(did);
  if (!m) {
    throw new Error(`Not a did:key identifier: ${did}`);
  }
  const bytes = bs58.decode(m[1].slice(1)); // strip the leading 'z'
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error(`did:key is not an Ed25519 public key: ${did}`);
  }
  return jose.base64url.encode(bytes.slice(2));
}

async function main() {
  const signedMandatePath = path.join(__dirname, "signed_mandate.json");
  const publicJwkPath = path.join(__dirname, "public_jwk.json");

  if (!fs.existsSync(signedMandatePath) || !fs.existsSync(publicJwkPath)) {
    console.error("Please run sign_proof.ts first.");
    process.exit(1);
  }

  const signedMandate = JSON.parse(fs.readFileSync(signedMandatePath, "utf8"));
  const publicJwk = JSON.parse(fs.readFileSync(publicJwkPath, "utf8"));

  const issuerDid: string = signedMandate.issuer;
  console.log(`Verifying mandate issued by: ${issuerDid}`);

  // Bind the verification key to the DID.
  // did:key implies the key, so a signer-supplied JWK is only acceptable
  // if it is byte-identical to the key encoded in the DID. Anything else
  // means the verifier is being asked to trust an attacker's key.
  let didBoundX: string;
  try {
    didBoundX = didKeyToJwkX(issuerDid);
  } catch (err: any) {
    console.error(`❌ Verification FAILED: ${err.message}`);
    process.exit(1);
  }
  if (
    !publicJwk.x ||
    publicJwk.x !== didBoundX ||
    publicJwk.kty !== "OKP" ||
    publicJwk.crv !== "Ed25519"
  ) {
    console.error(
      "❌ SECURITY FAILURE: public_jwk.json does NOT correspond to the issuer's did:key.",
    );
    console.error(
      "   The verification key must be the key encoded in the DID itself. Refusing to verify.",
    );
    process.exit(1);
  }
  console.log("✅ Verification key is bound to the issuer DID (did:key).");

  // Extract JWS
  const jws = signedMandate.proof.jws;

  // Import Key
  const publicKey = await jose.importJWK(publicJwk, "EdDSA");

  try {
    // Strict encoding gate: jose's decoder accepts non-canonical base64url
    // (several strings decoding to the same bytes), so a tampered-looking
    // token string can still verify. RFC 7515 demands canonical encoding;
    // reject anything else before the signature check.
    assertCanonicalJws(jws);

    const { payload, protectedHeader } = await jose.compactVerify(
      jws,
      publicKey,
    );

    console.log("✅ Verification SUCCESS: JWS signature is valid.");
    console.log("Protected Header:", protectedHeader);

    // The signing key id must name the issuer's key, not someone else's.
    const expectedKid = issuerDid + "#key-1";
    if (protectedHeader.kid !== expectedKid) {
      throw new Error(
        `kid mismatch: expected '${expectedKid}', got '${protectedHeader.kid}'`,
      );
    }
    console.log("✅ Key ID (kid) matches the issuer DID.");

    const verifiedPayloadStr = new TextDecoder().decode(payload);
    const verifiedMandate = JSON.parse(verifiedPayloadStr);

    // Simple check: issuer matches
    if (verifiedMandate.issuer === signedMandate.issuer) {
      console.log("Payload match confirmed.");
    }

    // Hardening: Check Expiration
    if (verifiedMandate.exp) {
      const now = Math.floor(Date.now() / 1000);
      if (now > verifiedMandate.exp) {
        throw new Error(
          `Token expired at ${verifiedMandate.exp}, now is ${now}`,
        );
      }
      console.log("✅ Token is within expiration window.");
    } else {
      console.warn(
        "⚠️  Warning: Token has no expiration (exp) field. Rejected by policy.",
      );
      throw new Error("Missing 'exp' claim.");
    }

    // Hardening: Check JTI
    if (!verifiedMandate.jti) {
      throw new Error("Missing 'jti' claim (Replay Protection).");
    }
    console.log(`✅ JTI Present: ${verifiedMandate.jti}`);

    // Stateful Replay Protection (JTI Ledger)
    const ledgerPath = path.join(__dirname, ".jti_ledger.json");
    let ledger: Record<string, number> = {};
    if (fs.existsSync(ledgerPath)) {
      try {
        ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
      } catch (e) {}
    }

    const now = Math.floor(Date.now() / 1000);
    // Cleanup expired entries
    for (const [id, exp] of Object.entries(ledger)) {
      if (exp < now) delete ledger[id];
    }

    if (ledger[verifiedMandate.jti]) {
      throw new Error(
        `Mandate JTI '${verifiedMandate.jti}' already used. Replay detected.`,
      );
    }

    // Record JTI
    ledger[verifiedMandate.jti] = verifiedMandate.exp || now + 3600;
    fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2));
    console.log("✅ JTI Recorded in Ledger (Replay Protected).");
  } catch (err) {
    console.error("❌ Verification FAILED:", err);
    process.exit(1);
  }
}

main().catch(console.error);
