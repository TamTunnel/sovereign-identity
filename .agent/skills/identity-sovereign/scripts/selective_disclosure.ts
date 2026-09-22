import * as jose from "jose";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import dotenv from "dotenv";
import bs58 from "bs58";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load env from project root (same identity store as onboard.ts / sign_proof.ts)
const ROOT_DIR = path.resolve(__dirname, "../../../../");
const ENV_PATH = path.join(ROOT_DIR, ".env.agent");
dotenv.config({ path: ENV_PATH });

// Helper to generate salt
const generateSalt = () => {
  return crypto.randomBytes(16).toString("base64url");
};

// Helper to create a disclosure
// Disclosure format: [salt, key, value]
const createDisclosure = (key: string, value: any) => {
  const salt = generateSalt();
  return [salt, key, value];
};

// Helper to hash a disclosure
// Hash(canonical_json(disclosure))
const hashDisclosure = (disclosure: any[]) => {
  const disclosureJson = JSON.stringify(disclosure);
  const hash = crypto.createHash("sha256").update(disclosureJson).digest();
  return hash.toString("base64url"); // generic SD-JWT uses base64url usually
};

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

/** Load the onboarded identity. Fails loudly — never mints a throwaway key. */
async function loadIdentity() {
  const password = process.env.CLAW_PASSWORD;
  if (!password) {
    console.error(
      "❌ ERROR: CLAW_PASSWORD environment variable is required to unlock your identity.",
    );
    process.exit(1);
  }

  const encryptedKeyRaw = process.env.AGENT_ENCRYPTED_KEY;
  const did = process.env.AGENT_DID;

  if (!encryptedKeyRaw || !did) {
    console.error(
      "❌ No onboarded identity found. This script will NOT mint a throwaway identity.",
    );
    console.error(
      "   Run 'npx tsx .agent/skills/identity-sovereign/scripts/onboard.ts' first.",
    );
    process.exit(1);
  }

  try {
    const encryptedData = JSON.parse(encryptedKeyRaw);
    const privateKeyPem = decrypt(encryptedData, password);
    const privateKey = await jose.importPKCS8(privateKeyPem, "EdDSA", {
      extractable: true,
    });
    console.log("🔓 Identity Unlocked.");
    return { did, privateKey };
  } catch (err) {
    console.error(
      "❌ Critical Security Failure: Incorrect Password or Corrupted Key.",
      err,
    );
    process.exit(1);
  }
}

/** Attribute claims come from the owner — never hardcoded. */
function loadAttributeClaims(): Record<string, any> {
  const raw = process.env.AGENT_SD_CLAIMS;
  if (!raw) {
    console.error(
      "❌ No attribute claims configured. This script will NOT invent claims (e.g. a fake name or email).",
    );
    console.error(
      "   Set AGENT_SD_CLAIMS to a JSON object of the attributes you consent to make disclosable, e.g.:",
    );
    console.error(
      "   AGENT_SD_CLAIMS='{\"age_over_18\":true,\"residency\":\"US\"}' npx tsx .../selective_disclosure.ts age_over_18",
    );
    process.exit(1);
  }
  let claims: any;
  try {
    claims = JSON.parse(raw);
  } catch {
    console.error("❌ AGENT_SD_CLAIMS is not valid JSON.");
    process.exit(1);
  }
  if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
    console.error("❌ AGENT_SD_CLAIMS must be a JSON object of claim key/value pairs.");
    process.exit(1);
  }
  if (Object.keys(claims).length === 0) {
    console.error("❌ AGENT_SD_CLAIMS is empty — nothing to disclose.");
    process.exit(1);
  }
  return claims;
}

/** Derive the did:key for a public JWK (same construction as onboard.ts). */
function didFromPublicJwk(publicJwk: jose.JWK): string {
  if (!publicJwk.x) throw new Error("Invalid JWK: missing x");
  const xBytes = jose.base64url.decode(publicJwk.x);
  const multicodecPrefix = new Uint8Array([0xed, 0x01]);
  const didKeyBytes = new Uint8Array(multicodecPrefix.length + xBytes.length);
  didKeyBytes.set(multicodecPrefix);
  didKeyBytes.set(xBytes, multicodecPrefix.length);
  return `did:key:z${bs58.encode(didKeyBytes)}`;
}

async function main() {
  console.log("--- Generating SD-JWT ---");

  // 1. Identity: the onboarded agent identity (never a throwaway key)
  const { did, privateKey } = await loadIdentity();

  // Sanity: the private key must correspond to the stored DID
  const checkJwk = await jose.exportJWK(privateKey);
  const { d: _d, ...checkPub } = checkJwk;
  if (didFromPublicJwk(checkPub) !== did) {
    console.error("❌ Stored DID does not match the decrypted key. Identity store is corrupt.");
    process.exit(1);
  }

  // 2. Attribute claims: owner-supplied via AGENT_SD_CLAIMS (never hardcoded)
  const attributeClaims = loadAttributeClaims();

  // 3. Create Disclosures & Hashes
  const disclosures: string[] = [];

  const sdClaims: Record<string, any> = {
    _sd: [],
  };

  for (const [key, value] of Object.entries(attributeClaims)) {
    const disclosure = createDisclosure(key, value);
    const disclosureStr = JSON.stringify(disclosure);
    const disclosureB64 = Buffer.from(disclosureStr).toString("base64url");

    disclosures.push(disclosureB64);

    const hash = hashDisclosure(disclosure);
    sdClaims._sd.push(hash);
  }

  // 4. Create the JWT Payload (iss/sub = the onboarded identity)
  const payload = {
    iss: did,
    sub: did,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...sdClaims,
  };

  console.log(
    "JWT Payload (with hidden claims):",
    JSON.stringify(payload, null, 2),
  );

  // 5. Sign the JWT with the agent's real key
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", kid: did + "#key-1" })
    .sign(privateKey);

  // 6. Append Disclosures (The SD-JWT Format utils)
  // Format: <JWT>~<Disclosure1>~<Disclosure2>~...~<KeyBindingJWT>
  const sdJwt = `${jwt}~${disclosures.join("~")}~`;

  console.log("\nComplete SD-JWT:");
  console.log(sdJwt);

  console.log("\n--- Verifying & Selective Disclosure ---");

  // 7. Holder selects which claims to reveal (CLI args; default: none)
  const targetClaims = process.argv.slice(2).filter((a) => !a.startsWith("--"));
  console.log(
    targetClaims.length > 0
      ? `Scenario: Presenting ONLY ${targetClaims.map((c) => `'${c}'`).join(", ")} to a vendor.`
      : "Scenario: Presenting the token with NO disclosures revealed.",
  );

  const unknown = targetClaims.filter((c) => !(c in attributeClaims));
  if (unknown.length > 0) {
    console.error(`❌ Unknown claim(s) requested for reveal: ${unknown.join(", ")}`);
    console.error(`   Available claims: ${Object.keys(attributeClaims).join(", ")}`);
    process.exit(1);
  }

  const revealedDisclosures = disclosures.filter((d) => {
    const decoded = JSON.parse(Buffer.from(d, "base64url").toString());
    // decoded is [salt, key, value]
    return targetClaims.includes(decoded[1]);
  });

  // 8. Presentation
  // Format: <JWT>~<RevealedDisclosure1>~<RevealedDisclosure2>~
  const presentationSdJwt = `${jwt}~${revealedDisclosures.join("~")}~`;

  console.log("\nPresentation SD-JWT (Redacted):");
  console.log(presentationSdJwt);

  // 9. Verifier Logic
  // a. Split token
  const parts = presentationSdJwt.split("~");
  const receivedJwt = parts[0];
  const receivedDisclosures = parts.slice(1, -1); // remove last empty

  // b. Verify Signature of JWT against the public key of the onboarded identity
  const publicKey = await jose.importJWK(checkPub, "EdDSA");
  const { payload: verifiedPayload } = await jose.jwtVerify(
    receivedJwt,
    publicKey,
  );
  const vp = verifiedPayload as any;
  if (vp.iss !== did || vp.sub !== did) {
    console.error("❌ iss/sub do not match the onboarded identity DID.");
    process.exit(1);
  }
  console.log("\n✅ Base JWT Signature Verified (onboarded identity key).");

  // c. Verify Disclosures
  const recoveredClaims: Record<string, any> = {};

  const _sd = vp._sd || [];

  console.log("\nVerifying Disclosures:");
  for (const d of receivedDisclosures) {
    const decodedJson = Buffer.from(d, "base64url").toString();
    const decoded = JSON.parse(decodedJson); // [salt, key, value]

    // Re-hash check
    const hash = hashDisclosure(decoded);

    if (_sd.includes(hash)) {
      console.log(`  ✅ Verified Claim: "${decoded[1]}" = ${decoded[2]}`);
      recoveredClaims[decoded[1]] = decoded[2];
    } else {
      console.error(`  ❌ Hash mismatch for disclosure: ${decodedJson}`);
      process.exit(1);
    }
  }

  console.log("\nRecovered Claims View:");
  console.log(JSON.stringify(recoveredClaims, null, 2));

  if (Object.keys(recoveredClaims).length === 0) {
    console.log("  (Note: no claims were revealed)");
  }
}

main().catch(console.error);
