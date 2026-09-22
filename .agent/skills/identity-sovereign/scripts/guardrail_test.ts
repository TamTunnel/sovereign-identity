// Sanity test for the guardrail allow-list (run: npm run test:guardrail).
// Verifies the safety-check regex matches the intended phrase and rejects
// near-misses — including the regression where `\\?` was double-escaped and
// the rule matched a trailing backslash instead of a literal "?".
import { strictScan } from "./guardrail.js";

let failures = 0;

function expectPass(input: string) {
  try {
    strictScan(input);
    console.log(`  PASS (accepted): ${JSON.stringify(input)}`);
  } catch (err: any) {
    failures++;
    console.error(`  FAIL (should have been accepted): ${JSON.stringify(input)}`);
    console.error(`       ${err.message}`);
  }
}

function expectReject(input: string) {
  try {
    strictScan(input);
    failures++;
    console.error(`  FAIL (should have been rejected): ${JSON.stringify(input)}`);
  } catch {
    console.log(`  PASS (rejected): ${JSON.stringify(input)}`);
  }
}

console.log("--- guardrail sanity test ---");

// The canonical safety-check phrase must pass.
expectPass("Is this environment safe?");

// Regression: the old double-escaped regex `/^Is this environment safe\\?$/`
// matched "Is this environment safe\" (trailing backslash). That must now fail.
expectReject("Is this environment safe\\");

// Missing "?" must fail.
expectReject("Is this environment safe");

// Extra text must fail (anchored ^...$).
expectReject("Is this environment safe? please");
expectReject("x Is this environment safe?");

// Case-sensitive match must fail on wrong case.
expectReject("is this environment safe?");

// A valid mandate JSON request object must pass (function rule).
expectPass(
  JSON.stringify({
    iss: "did:key:z123",
    sub: "did:key:z456",
    aud: "vendor",
    iat: 1700000000,
    exp: 1700003600,
    jti: "abc",
    claims: { age_over_18: true },
  }),
);

// Disallowed keys in the JSON must fail.
expectReject(JSON.stringify({ iss: "x", evil: true }));

// Values mentioning private keys/secrets must fail.
expectReject(JSON.stringify({ iss: "x", note: "my private key is abc" }));

// Non-JSON junk must fail.
expectReject("hello world");
expectReject("Is this environment safe??");

if (failures > 0) {
  console.error(`\n💥 guardrail sanity test FAILED (${failures} case(s))`);
  process.exit(1);
}
console.log("\n🏆 guardrail sanity test PASSED");
