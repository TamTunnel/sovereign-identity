import * as jose from "jose";
import bs58 from "bs58";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ENV_PATH = path.join(__dirname, "../../.env.agent");

async function main() {
  console.log("🚀 Starting OpenClaw Identity Onboarding...");

  if (fs.existsSync(ENV_PATH)) {
    console.log("✅ Identity found in .env.agent. You are ready to go!");
    // Verify key exists?
    // For now just exit.
    return;
  }

  console.log("⚠️  No identity found. Generating a new Master Identity...");

  // 1. Generate Ed25519 Key Pair
  const { publicKey, privateKey } = await jose.generateKeyPair("EdDSA", {
    crv: "Ed25519",
  });

  // 2. Export Private Key to PKCS8 PEM for storage
  const privateKeyStart = await jose.exportPKCS8(privateKey);
  // 3. Export Public Key to JWK for DID construction
  const publicJwk = await jose.exportJWK(publicKey);

  // 4. Construct DID (Using same logic as sign_proof.ts for consistency)
  if (!publicJwk.x) throw new Error("Invalid JWK");
  const xBytes = jose.base64url.decode(publicJwk.x);
  const multicodecPrefix = new Uint8Array([0xed, 0x01]);
  const didKeyBytes = new Uint8Array(multicodecPrefix.length + xBytes.length);
  didKeyBytes.set(multicodecPrefix);
  didKeyBytes.set(xBytes, multicodecPrefix.length);
  const didIdentifier = bs58.encode(didKeyBytes);
  const did = `did:key:z${didIdentifier}`;

  console.log(`\n🔑 New DID Generated: ${did}`);

  // 5. Save to .env.agent
  const envContent = `AGENT_DID=${did}\nAGENT_PRIVATE_KEY="${privateKeyStart.replace(/\n/g, "\\n")}"\n`;

  // Ensure .agent root exists (it should if we are running this)
  // The path is ../../.env.agent relative to scripts/
  // skills/identity-sovereign/scripts -> skills/identity-sovereign -> skills -> .agent
  // Actually typically .env could be in project root or .agent root.
  // Let's put it in the skill root for now to be self-contained or better yet:
  // User requested ".agent/ folder" check.
  // Let's assume the root of the repo relative to this script is:
  // scripts -> identity-sovereign -> skills -> .agent
  // So ../../../ would be .agent/

  // BUT the requirement Says: "check for existing DIDs in the .agent/ folder"
  // And "save it to a local .env.agent file".

  // Let's stick to the skill directory for the file for defined scope,
  // OR checking if a global one exists?
  // Let's create it in the root of the "skill repo" which is `openclaw-identity-skill/`
  // So that would be ../../ from `scripts` (scripts -> identity-sovereign -> skills -> .agent -> openclaw-identity-skill?? NO)

  // Structure:
  // openclaw-identity-skill/
  //   .agent/
  //     skills/
  //       identity-sovereign/
  //         scripts/

  // So to get to `openclaw-identity-skill/` (root), we need `../../../..`
  // scripts(1) -> identity-sovereign(2) -> skills(3) -> .agent(4) -> root

  const rootDir = path.resolve(__dirname, "../../../../");
  const envFileTarget = path.join(rootDir, ".env.agent");

  fs.writeFileSync(envFileTarget, envContent);
  console.log(`✅ Private Key saved to ${envFileTarget}`);
  console.log("🔒 This file is gitignored. NEVER share it.");

  console.log("\nOnboarding Complete! Run 'npm test' to verify.");
}

main().catch(console.error);
