/**
 * SARIF 2.1.0 output so `defenso-scan --sarif` drops straight into GitHub
 * Advanced Security code scanning (upload-sarif action) and other SARIF
 * consumers. One rule per template id; one result per finding.
 */
const SEV_TO_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'warning', info: 'note' };
const SEV_TO_SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

export function toSarif(report) {
  const ruleMap = new Map();
  const results = [];

  for (const f of report.findings) {
    if (!ruleMap.has(f.id)) {
      ruleMap.set(f.id, {
        id: f.id,
        name: f.name,
        shortDescription: { text: f.name },
        fullDescription: { text: f.remediation || f.name },
        helpUri: f.reference || 'https://defen.so/online-website-security-scanner',
        properties: {
          tags: [...(f.tags || []), f.cwe].filter(Boolean),
          'security-severity': SEV_TO_SCORE[f.severity] || '1.0',
        },
        defaultConfiguration: { level: SEV_TO_LEVEL[f.severity] || 'note' },
      });
    }
    results.push({
      ruleId: f.id,
      level: SEV_TO_LEVEL[f.severity] || 'note',
      message: { text: `${f.name}: ${f.evidence}${f.remediation ? ' Fix: ' + f.remediation : ''}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: report.url },
        },
      }],
      properties: { severity: f.severity, cwe: f.cwe },
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'defenso-scan',
          version: report.version,
          informationUri: 'https://defen.so/online-website-security-scanner',
          rules: [...ruleMap.values()],
        },
      },
      results,
    }],
  };
}
