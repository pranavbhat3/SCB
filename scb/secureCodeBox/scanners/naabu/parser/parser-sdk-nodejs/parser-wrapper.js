// SPDX-FileCopyrightText: the secureCodeBox authors
//
// SPDX-License-Identifier: Apache-2.0

const axios = require("axios");

/**
 * This is the real parser logic. When used inside Kubernetes,
 * it connects to the k8s API and uploads results, etc.
 * But for local usage (e.g. Docker with STDIN), we export createParser below.
 */
async function parse(rawData) {
  // Return findings here. You can enrich or normalize as needed.
  const findings = [];

  // Example parsing logic for TLSX JSON
  const finding = {
    name: "TLS Scan Result",
    description: `Found TLS info for ${rawData.host}`,
    category: "TLS",
    location: `${rawData.host}:${rawData.port}`,
    osi_layer: "APPLICATION",
    severity: "INFORMATIONAL",
    attributes: {
      tls_version: rawData.tls_version,
      cipher: rawData.cipher,
      subject: rawData.subject_dn,
      issuer: rawData.issuer_dn,
      sni: rawData.sni,
      fingerprint: rawData.fingerprint_hash,
    },
  };

  findings.push(finding);
  return findings;
}

// 👇 Main SecureCodeBox SDK-style export:
module.exports = {
  createParser: function (parserFunction) {
    return async function runParser({ input, output, findings }) {
      const jsonInput = JSON.parse(input);
      const results = await parserFunction(jsonInput);

      for (const finding of results) {
        findings.push(finding);
      }
    };
  },
};
