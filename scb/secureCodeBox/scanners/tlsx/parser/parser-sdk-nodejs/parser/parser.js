module.exports = async ({ input, registerFinding }) => {
  const data = JSON.parse(input);
  registerFinding({
    name: "TLSX Dummy Finding",
    description: `Parsed ${data.length || 1} entries`,
    severity: "INFORMATIONAL",
    category: "TLSX Result",
    location: data[0]?.ip || "Unknown",
    osi_layer: "NETWORK",
  });
};
