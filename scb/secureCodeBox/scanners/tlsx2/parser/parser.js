const readline = require("readline");

async function readInput() {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  const lines = [];

  for await (const line of rl) {
    if (line.trim().startsWith("{")) {
      lines.push(line.trim());
    }
  }

  rl.close();

  return lines;
}

(async () => {
  const rawLines = await readInput();

  if (!rawLines.length) {
    console.error("❌ No valid JSON objects found in input.");
    process.exit(1);
  }
  console.log("✅ Raw input received:");
  const jsonObjects = rawLines.map(JSON.parse);

  for (const entry of jsonObjects) {
    if (!entry.host) continue;

    const finding = {
      name: `TLSX Result for ${entry.host}`,
      description: `TLS version ${entry.tls_version} with cipher ${entry.cipher}`,
      category: "TLS Certificate Info",
      location: `${entry.host}:${entry.port}`,
      osi_layer: "NETWORK",
      severity: "LOW",
      attributes: entry,
    };

    console.log("📝 Parsed Finding:");
    console.log(JSON.stringify(finding, null, 2));
  }
})();
