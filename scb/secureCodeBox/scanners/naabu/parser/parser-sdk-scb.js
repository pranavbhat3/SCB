const { createParser } = require("./parser-sdk-nodejs/parser-wrapper");
const readline = require("readline");
const fs = require("fs");

async function parse(rawInput) {
  let lines = [];
  if (Array.isArray(rawInput)) {
    lines = rawInput;
  } else if (typeof rawInput === "string") {
    lines = rawInput.split('\n').filter(line => line.trim().startsWith('{'));
  }
  const findings = [];
  for (const line of lines) {
    let entry;
    try {
      entry = typeof line === "string" ? JSON.parse(line) : line;
    } catch (e) { continue; }
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
  return findings;
}

module.exports = createParser(async ({ input }) => {
  // input is a string with all lines
  return await parse(input);
}); 