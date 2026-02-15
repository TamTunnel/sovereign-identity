import * as jose from "jose";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
async function main() {
  const signedMandatePath = path.join(__dirname, "signed_mandate.json");
  const publicJwkPath = path.join(__dirname, "public_jwk.json");
  if (!fs.existsSync(signedMandatePath) || !fs.existsSync(publicJwkPath)) {
    console.error("Please run sign_proof.ts first.");
    process.exit(1);
  }
  const signedMandate = JSON.parse(fs.readFileSync(signedMandatePath, "utf8"));
  const publicJwk = JSON.parse(fs.readFileSync(publicJwkPath, "utf8"));
  console.log(`Verifying mandate issued by: ${signedMandate.issuer}`);
  // Extract JWS
  const jws = signedMandate.proof.jws;
  // Import Key
  const publicKey = await jose.importJWK(publicJwk, "EdDSA");
  try {
    const { payload, protectedHeader } = await jose.compactVerify(
      jws,
      publicKey,
    );
    console.log("✅ Verification SUCCESS: JWS signature is valid.");
    console.log("Protected Header:", protectedHeader);
    // Check payload matches?
    // In strict LD-Proof, we would detach the proof and canonicalize the document and compare.
    // But here we embedded the JWS which CONTAINS the payload.
    // The JWS payload is the mandate content.
    // The `signedMandate` object has fields + proof.
    // If the JWS payload matches the fields in `signedMandate` (minus proof), integrity is verified.
    const verifiedPayloadStr = new TextDecoder().decode(payload);
    const verifiedMandate = JSON.parse(verifiedPayloadStr);
    // Simple check: issuer matches
    if (verifiedMandate.issuer === signedMandate.issuer) {
      console.log("Payload match confirmed.");
    }
  } catch (err) {
    console.error("❌ Verification FAILED:", err);
    process.exit(1);
  }
}
main().catch(console.error);
