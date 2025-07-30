const fs = require("fs");
const readline = require("readline");
const http = require("http");
const https = require("https");

function isUrl(str) {
  return /^https?:\/\//.test(str);
}

async function downloadToMemory(url) {
  const proto = url.startsWith("https") ? https : http;
  return new Promise((resolve, reject) => {
    let data = '';
    proto.get(url, (response) => {
      if (response.statusCode !== 200) {
        console.error(`❌ Failed to get '${url}' (status: ${response.statusCode})`);
        response.resume(); // Drain response
        reject(new Error(`Failed to get '${url}' (${response.statusCode})`));
        return;
      }
      response.setEncoding('utf8');
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => resolve(data));
    }).on("error", (err) => {
      console.error(`❌ HTTP request error for '${url}':`, err);
      reject(err);
    });
  });
}

async function readInputFromFile(filePath) {
  const rl = readline.createInterface({
    input: fs.createReadStream(filePath),
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

async function readInputFromStdin() {
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
  let rawLines = [];
  const arg = process.argv[2];
  if (arg) {
    if (isUrl(arg)) {
      // Download file from URL into memory
      try {
        const data = await downloadToMemory(arg);
        // Split into lines and filter JSON objects
        rawLines = data.split('\n').filter(line => line.trim().startsWith("{"));
      } catch (err) {
        console.error("❌ Failed to download or read input from URL:", err);
        process.exit(1);
      }
    } else {
      // Read from local file
      try {
        rawLines = await readInputFromFile(arg);
      } catch (err) {
        console.error("❌ Failed to read input from file:", err);
        process.exit(1);
      }
    }
  } else {
    // Read from stdin
    rawLines = await readInputFromStdin();
  }

  if (!rawLines.length) {
    console.error("❌ No valid JSON objects found in input.");
    process.exit(1);
  }

  const jsonObjects = rawLines.map(JSON.parse);
  const findings = [];

  for (const entry of jsonObjects) {
    if (!entry.host) continue;
    findings.push({
      name: `TLSX Result for ${entry.host}`,
      description: `TLS version ${entry.tls_version} with cipher ${entry.cipher}`,
      category: "TLS Certificate Info",
      location: `${entry.host}:${entry.port}`,
      osi_layer: "NETWORK",
      severity: "LOW",
      attributes: entry,
    });
  }

  // Output a single JSON array of findings to stdout
  process.stdout.write(JSON.stringify(findings, null, 2));
  // Also write findings to a local file for debugging
  try {
    fs.writeFileSync('findings-local.json', JSON.stringify(findings, null, 2));
  } catch (err) {
    console.error('❌ Failed to write findings-local.json:', err);
  }
})();
