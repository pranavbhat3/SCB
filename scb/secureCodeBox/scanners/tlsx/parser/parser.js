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

async function uploadToMinio(findingsJson) {
  const endpoint = process.env.MINIO_ENDPOINT;
  const accessKey = process.env.MINIO_ACCESS_KEY;
  const secretKey = process.env.MINIO_SECRET_KEY;
  const bucket = process.env.MINIO_BUCKET;
  const secure = process.env.MINIO_SECURE === "true";
  const scanFolder = process.env.SCAN_RESULT_FOLDER || process.env.SCAN_UID || "";

  if (!endpoint || !accessKey || !secretKey || !bucket) {
    console.error("[MinIO] Missing required environment variables, skipping direct upload.");
    return;
  }

  // Try to extract scan folder from CWD if not set
  let folder = scanFolder;
  if (!folder) {
    // Try to guess from working directory (e.g., /home/securecodebox/scan-<uid>)
    const cwd = process.cwd();
    const match = cwd.match(/scan-([a-f0-9\-]+)/);
    if (match) folder = `scan-${match[1]}`;
  }
  if (!folder) folder = "";

  const Minio = require("minio");
  const minioClient = new Minio.Client({
    endPoint: endpoint.replace(/^https?:\/\//, "").split(":")[0],
    port: parseInt(endpoint.split(":").pop(), 10),
    useSSL: secure,
    accessKey,
    secretKey,
  });
  const objectName = folder ? `${folder}/findings.json` : "findings.json";
  try {
    await minioClient.putObject(bucket, objectName, findingsJson);
    console.log(`[MinIO] Uploaded findings.json to bucket '${bucket}' at '${objectName}'`);
  } catch (err) {
    console.error(`[MinIO] Failed to upload findings.json:`, err);
  }
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
  const findingsJson = JSON.stringify(findings, null, 2);
  process.stdout.write(findingsJson);

  // Write findings.json to /home/securecodebox/findings.json for in-cluster use
  try {
    fs.writeFileSync('/home/securecodebox/findings.json', findingsJson);
    console.log('[Parser] Wrote findings.json to /home/securecodebox/findings.json');
  } catch (err) {
    console.error('[Parser] Failed to write findings.json:', err);
  }

  // Try to upload to MinIO if credentials are present
  try {
    await uploadToMinio(findingsJson);
  } catch (err) {
    console.error("[MinIO] Upload error:", err);
  }
})();
