const fs = require("fs");
const readline = require("readline");
const https = require("https");
const http = require("http");

async function downloadFromUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    client.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        resolve(data);
      });
    }).on('error', (err) => {
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

async function readInputFromUrl(url) {
  const data = await downloadFromUrl(url);
  const lines = data.split('\n').filter(line => line.trim().startsWith('{'));
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
  let inputSource = process.argv[2] || '/home/securecodebox/raw-results.json';
  
  try {
    if (inputSource.startsWith('http://') || inputSource.startsWith('https://')) {
      console.log(`[Parser] Downloading from URL: ${inputSource}`);
      rawLines = await readInputFromUrl(inputSource);
    } else {
      console.log(`[Parser] Reading from file: ${inputSource}`);
      rawLines = await readInputFromFile(inputSource);
    }
  } catch (err) {
    console.error("❌ Failed to read input:", err);
    process.exit(1);
  }

  if (!rawLines.length) {
    console.error("❌ No valid JSON objects found in input.");
    process.exit(1);
  }

  console.log(`[Parser] Found ${rawLines.length} JSON lines`);

  const jsonObjects = rawLines.map(JSON.parse);
  const findings = [];

  for (const entry of jsonObjects) {
    if (!entry.ip || !entry.port) continue;
    findings.push({
      name: `Open port ${entry.port} on ${entry.ip}`,
      description: `Port ${entry.port} is open on host ${entry.ip}`,
      category: "Open Port",
      location: `${entry.ip}:${entry.port}`,
      osi_layer: "NETWORK",
      severity: "INFORMATIONAL",
      attributes: entry,
    });
  }

  console.log(`[Parser] Generated ${findings.length} findings`);

  const findingsJson = JSON.stringify(findings, null, 2);
  process.stdout.write(findingsJson);

  // Write findings.json to /home/securecodebox/findings.json for PVC extraction
  try {
    fs.writeFileSync('/home/securecodebox/findings.json', findingsJson);
    console.log('[Parser] Wrote findings.json to /home/securecodebox/findings.json');
  } catch (err) {
    console.error('[Parser] Failed to write findings.json:', err);
  }
})(); 