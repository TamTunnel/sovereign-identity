import * as jose from "jose";
import bs58 from "bs58";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load env from project root
const ROOT_DIR = path.resolve(__dirname, "../../../../");
const ENV_PATH = path.join(ROOT_DIR, ".env.agent");
dotenv.config({ path: ENV_PATH });

const MANDATE_PATH = path.join(__dirname, "../schema/mandate.json");

function decrypt(encryptedData: any, password: string): string {
  const salt = Buffer.from(encryptedData.salt, "hex");
  const iv = Buffer.from(encryptedData.iv, "hex");
  const authTag = Buffer.from(encryptedData.authTag, "hex");
  const encryptedText = encryptedData.content;

  const key = crypto.scryptSync(password, salt, 32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

async function main() {
  const password = process.env.CLAW_PASSWORD;
  if (!password) {
    console.error(
      "❌ ERROR: CLAW_PASSWORD environment variable is required to sign mandates.",
    );
    process.exit(1);
  }

  // 1. Load Encrypted Identity
  const encryptedKeyRaw = process.env.AGENT_ENCRYPTED_KEY;
  const did = process.env.AGENT_DID;

  if (!encryptedKeyRaw || !did) {
    console.error(
      "❌ No identity found. Run 'npx tsx scripts/onboard.ts' first.",
    );
    process.exit(1);
  }

  let privateKey: CryptoKey;
  try {
    const encryptedData = JSON.parse(encryptedKeyRaw);
    const privateKeyPem = decrypt(encryptedData, password);
    // FIX: Must make key extractable to export JWK later
    privateKey = await jose.importPKCS8(privateKeyPem, "EdDSA", {
      extractable: true,
    });
    console.log("🔓 Identity Unlocked.");
  } catch (err) {
    console.error(
      "❌ Critical Security Failure: Incorrect Password or Corrupted Key.",
      err,
    );
    process.exit(1);
  }

  // 4. Load Mandate template from schema/mandate.json
  const schemaDoc = JSON.parse(fs.readFileSync(MANDATE_PATH, "utf8"));
  if (typeof schemaDoc.example !== "object" || schemaDoc.example === null) {
    console.error(
      "❌ schema/mandate.json is missing its 'example' mandate template.",
    );
    process.exit(1);
  }
  const mandate = { ...schemaDoc.example };

  mandate.issuer = did;
  mandate.issuanceDate = new Date().toISOString();
  // Hardening: Add Expiration and JTI
  mandate.exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour expiration
  mandate.jti = crypto.randomUUID();

  // Validate the fields the schema requires on a signable mandate
  const requiredFields: string[] = Array.isArray(schemaDoc.required)
    ? schemaDoc.required
    : ["issuer", "issuanceDate", "exp", "jti"];
  const missing = requiredFields.filter(
    (f: string) => mandate[f] === undefined || mandate[f] === null,
  );
  if (missing.length > 0) {
    console.error(
      `❌ Mandate template is missing required fields: ${missing.join(", ")}`,
    );
    process.exit(1);
  }

  // 5. Sign Mandate
  const payloadStr = JSON.stringify(mandate);
  const payloadBytes = new TextEncoder().encode(payloadStr);

  const jws = await new jose.CompactSign(payloadBytes)
    .setProtectedHeader({ alg: "EdDSA", kid: did + "#key-1" })
    .sign(privateKey);

  // Attach proof
  mandate.proof = {
    type: "JwsSignature2020",
    verificationMethod: did + "#key-1",
    created: new Date().toISOString(),
    proofPurpose: "assertionMethod",
    jws: jws,
  };

  console.log("Signed Mandate:");
  console.log(JSON.stringify(mandate, null, 2));

  // Save signed mandate
  fs.writeFileSync(
    path.join(__dirname, "signed_mandate.json"),
    JSON.stringify(mandate, null, 2),
  );

  // Export JWK for verification
  // This requires the privateKey to be extractable
  const jwk = await jose.exportJWK(privateKey);
  const { d, ...publicJwk } = jwk; // Remove private part 'd'

  fs.writeFileSync(
    path.join(__dirname, "public_jwk.json"),
    JSON.stringify(publicJwk, null, 2),
  );
}

main().catch(console.error);
