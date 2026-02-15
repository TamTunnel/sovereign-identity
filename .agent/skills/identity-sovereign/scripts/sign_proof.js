import * as jose from "jose";
import bs58 from "bs58";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MANDATE_PATH = path.join(__dirname, "../schema/mandate.json");
async function main() {
  // 1. Generate Ed25519 Key Pair
  const { publicKey, privateKey } = await jose.generateKeyPair("EdDSA", {
    crv: "Ed25519",
  });
  // 2. Export Public Key to JWK to construct DID
  const jwk = await jose.exportJWK(publicKey);
  if (!jwk.x) {
    throw new Error("Invalid Ed25519 public key JWK: missing 'x'");
  }
  // 3. Construct did:key
  // Decode base64url 'x' to bytes
  const xBytes = jose.base64url.decode(jwk.x);
  // multicodec prefix for Ed25519 public key in multiformats is 0xed 0x01 (varint 237)
  const multicodecPrefix = new Uint8Array([0xed, 0x01]);
  const didKeyBytes = new Uint8Array(multicodecPrefix.length + xBytes.length);
  didKeyBytes.set(multicodecPrefix);
  didKeyBytes.set(xBytes, multicodecPrefix.length);
  const didIdentifier = bs58.encode(didKeyBytes);
  const did = `did:key:z${didIdentifier}`;
  console.log(`Generated DID: ${did}`);
  // 4. Load Mandate
  const mandateRaw = fs.readFileSync(MANDATE_PATH, "utf8");
  const mandate = JSON.parse(mandateRaw);
  mandate.issuer = did;
  mandate.issuanceDate = new Date().toISOString();
  // 5. Sign Mandate
  // We'll use a detached JWS style or just raw signature if we want to mimic LD-Architectures manually.
  // For simplicity here, we'll create a Compact JWS but extract the signature part if needed,
  // or just attach the full JWS as `proof` value if the schema supported it.
  // The schema asks for "signatureValue" which usually implies raw signature bytes in hex or base58.
  // But standard Ed25519Signature2020 suite is complex.
  // Let's just sign the canonical string (JSON.stringify) for this demo.
  const payloadStr = JSON.stringify(mandate);
  const payloadBytes = new TextEncoder().encode(payloadStr);
  // Create a JWS. It allows us to use standard verifying tools.
  const jws = await new jose.CompactSign(payloadBytes)
    .setProtectedHeader({ alg: "EdDSA", kid: did + "#key-1" })
    .sign(privateKey);
  // Attach proof
  mandate.proof = {
    type: "JwsSignature2020", // Changing from Ed25519Signature2020 to clarify it's JWS based
    verificationMethod: did + "#key-1",
    created: new Date().toISOString(),
    proofPurpose: "assertionMethod",
    jws: jws, // We use `jws` property for JWS proofs
  };
  console.log("Signed Mandate:");
  console.log(JSON.stringify(mandate, null, 2));
  // Save signed mandate
  fs.writeFileSync(
    path.join(__dirname, "signed_mandate.json"),
    JSON.stringify(mandate, null, 2),
  );
  // Export JWK for verification (simplification)
  // In real DID world, verifier resolves DID to get JWK.
  fs.writeFileSync(
    path.join(__dirname, "public_jwk.json"),
    JSON.stringify(jwk, null, 2),
  );
}
main().catch(console.error);
