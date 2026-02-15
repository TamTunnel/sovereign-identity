const FORBIDDEN_KEYWORDS = [
  "private key",
  "seed phrase",
  "mnemonic",
  "password",
  "secret key",
  "access token",
];

function scanForSafety(input: string) {
  const lowerInput = input.toLowerCase();
  for (const keyword of FORBIDDEN_KEYWORDS) {
    if (lowerInput.includes(keyword)) {
      throw new Error(
        `SECURITY ALERT: Forbidden keyword detected: "${keyword}". Session terminated.`,
      );
    }
  }
  console.log("✅ Safety Check Passed.");
}

// Example usage checking command line args
const args = process.argv.slice(2);
if (args.length > 0) {
  try {
    scanForSafety(args.join(" "));
  } catch (error: any) {
    console.error(error.message);
    process.exit(1);
  }
}
