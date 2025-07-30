// parser.js (No SDK)
const fs = require('fs');

// Read from stdin manually
let inputData = '';

process.stdin.on('data', chunk => {
  inputData += chunk;
});

process.stdin.on('end', () => {
  console.log("✅ Raw input received:");
  console.log(inputData);

  let json;
  try {
    json = JSON.parse(inputData);
  } catch (err) {
    console.error("❌ JSON parse error:", err.message);
    process.exit(1);
  }

  if (!json || !json.host) {
    console.error("❌ Invalid JSON or missing 'host'");
    process.exit(1);
  }

  const finding = {
    name: `TLSX Result for ${json.host}`,
    description: `TLS version ${json.tls_version} with cipher ${json.cipher}`,
    category: "TLS Certificate Info",
    location: `${json.host}:${json.port}`,
    osi_layer: "NETWORK",
    severity: json.self_signed ? "LOW" : "INFORMATIONAL",
    attributes: json
  };

  console.log("📝 Parsed Finding:");
  console.log(JSON.stringify(finding, null, 2));
});
