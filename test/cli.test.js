'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var childProcess = require('child_process');
var PasteShieldCore = require('../sanitizer-core');

var CLI_PATH = path.join(__dirname, '..', 'bin', 'pasteshield-cli.js');
var SCRATCH_DIR = path.join(__dirname, '.scratch-test');

function cleanup() {
  if (fs.existsSync(SCRATCH_DIR)) {
    fs.rmSync(SCRATCH_DIR, { recursive: true, force: true });
  }
}

cleanup();
fs.mkdirSync(SCRATCH_DIR, { recursive: true });

try {
  // 1. Core library bidirectional roundtrip
  var vault = PasteShieldCore.createVault();
  var raw = [
    'OPENAI_API_KEY=sk-proj-EXAMPLE000000000000000000000002',
    'DATABASE_URL="postgres://admin:S3cr3tPass!@192.168.10.25:5432/app"',
    'GITHUB_TOKEN=ghp_EXAMPLE00000000000000000000000002',
    'CONTACT=devops@example-corp.io'
  ].join('\n');

  var san = vault.sanitize(raw);
  assert.strictEqual(san.changed, true);
  assert.strictEqual(san.totalRedactions, 4);
  assert.ok(san.sanitizedText.indexOf('sk-proj-') === -1, 'OpenAI key must be redacted');
  assert.ok(san.sanitizedText.indexOf('S3cr3tPass!') === -1, 'DB password must be redacted');
  assert.ok(san.sanitizedText.indexOf('<OPENAI_KEY_1>') !== -1);
  assert.ok(san.sanitizedText.indexOf('<DB_URI_1>') !== -1);

  var restored = vault.restore(san.sanitizedText);
  assert.strictEqual(restored.restoredText, raw, 'Exact lossless bidirectional restoration');

  // 2. CLI sanitize -> vault -> restore roundtrip via stdin/stdout
  var vaultFile = path.join(SCRATCH_DIR, 'session.vault.json');
  var sanitizedStdout = childProcess.execFileSync(
    process.execPath,
    [CLI_PATH, 'sanitize', '--vault', vaultFile, '--quiet'],
    { input: raw, encoding: 'utf8' }
  );
  assert.strictEqual(sanitizedStdout, san.sanitizedText);

  var aiRefactor = 'const cfg = { key: "<OPENAI_KEY_1>", db: "<DB_URI_1>" };\n';
  var restoredStdout = childProcess.execFileSync(
    process.execPath,
    [CLI_PATH, 'restore', '--vault', vaultFile, '--quiet'],
    { input: aiRefactor, encoding: 'utf8' }
  );
  assert.ok(restoredStdout.indexOf('sk-proj-EXAMPLE000000000000000000000002') !== -1);
  assert.ok(restoredStdout.indexOf('postgres://admin:S3cr3tPass!@192.168.10.25:5432/app') !== -1);

  // 3. CLI demo command succeeds cleanly
  var demoOut = childProcess.execFileSync(process.execPath, [CLI_PATH, 'demo'], { encoding: 'utf8' });
  assert.ok(demoOut.indexOf('1-CLICK LOCAL RESTORATION') !== -1);

  // 4. Issue #23/#24: package.json bin matches package name for npx auto-resolution
  var pkgJson = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.strictEqual(pkgJson.bin[pkgJson.name], './bin/pasteshield-cli.js', 'bin[pkg.name] must resolve for npx github:... --mcp');

  // 5. Issue #24: Mocked Gumroad verify fetch unlocks Pro custom domain rules in BOTH CLI (--license) and MCP ($PASTESHIELD_LICENSE)
  var mockPreload = path.join(SCRATCH_DIR, 'mock-gumroad-fetch.js');
  fs.writeFileSync(mockPreload, [
    'globalThis.fetch = async function (url, opts) {',
    '  var b = String((opts && opts.body) || "");',
    '  var ok = url === "https://api.gumroad.com/v2/licenses/verify" && b.indexOf("GUMROAD-MOCK-PRO-KEY-7777") !== -1 && b.indexOf("pasteshield-pro") !== -1;',
    '  return { json: async function () { return ok ? { success: true, purchase: { permalink: "pasteshield-pro", refunded: false } } : { success: false }; } };',
    '};'
  ].join('\n'), 'utf8');

  var proCliOut = childProcess.execFileSync(
    process.execPath,
    ['--require', mockPreload, CLI_PATH, 'sanitize', '--domain', 'corp.acme.internal', '--license', 'GUMROAD-MOCK-PRO-KEY-7777', '--quiet'],
    { input: 'ENDPOINT=https://payments.corp.acme.internal/v1', encoding: 'utf8' }
  );
  assert.strictEqual(proCliOut.trim(), 'ENDPOINT=https://<COMPANY_DOMAIN_1>/v1', 'CLI --license awaits Gumroad verify and unlocks Pro domain redaction');

  var auditSampleDir = path.join(SCRATCH_DIR, 'audit-target');
  fs.mkdirSync(auditSampleDir, { recursive: true });
  fs.writeFileSync(
    path.join(auditSampleDir, 'deploy.yaml'),
    'ingress: https://billing.corp.acme.internal/settle\nticket: FINOPS-4096\n',
    'utf8'
  );

  var mcpRes = childProcess.spawnSync(
    process.execPath,
    ['--require', mockPreload, CLI_PATH, '--mcp'],
    {
      env: Object.assign({}, process.env, { PASTESHIELD_LICENSE: 'GUMROAD-MOCK-PRO-KEY-7777' }),
      input: [
        JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }),
        JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'sanitize_snippet', arguments: { text: 'HOST=api.corp.acme.internal', companyDomains: ['corp.acme.internal'] } } }),
        JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'audit_workspace_secrets', arguments: { targetPath: auditSampleDir, companyDomains: ['corp.acme.internal'], customPatterns: ['CORP_TICKET::FINOPS-\\d{4}'] } } })
      ].join('\n') + '\n',
      encoding: 'utf8',
      timeout: 8000
    }
  );
  var mcpLines = mcpRes.stdout.trim().split('\n').map(function (l) { return JSON.parse(l); });
  var mcpPayload = JSON.parse(mcpLines[1].result.content[0].text);
  assert.strictEqual(mcpPayload.proActive, true, 'MCP server awaits Gumroad verify and activates Pro');
  assert.strictEqual(mcpPayload.sanitizedText, 'HOST=<COMPANY_DOMAIN_1>', 'MCP Pro custom domain redaction works');

  var mcpAudit = JSON.parse(mcpLines[2].result.content[0].text);
  assert.strictEqual(mcpAudit.proActive, true, 'MCP audit_workspace_secrets activates Pro');
  var auditCats = mcpAudit.findings.map(function (f) { return f.category; });
  assert.ok(auditCats.indexOf('COMPANY_DOMAIN') !== -1, 'MCP audit_workspace_secrets detects Pro COMPANY_DOMAIN');
  assert.ok(auditCats.indexOf('CORP_TICKET') !== -1, 'MCP audit_workspace_secrets detects Pro customPatterns');
  assert.ok(Boolean(mcpAudit.findings[0].maskedPreview), 'MCP audit_workspace_secrets populates maskedPreview');

  // 6. Issue #57: init-policy & .pasteshield.json repo policy auto-loading
  var policyPath = path.join(SCRATCH_DIR, '.pasteshield.json');
  childProcess.execFileSync(process.execPath, [CLI_PATH, 'init-policy', '--policy', policyPath], { encoding: 'utf8' });
  assert.ok(fs.existsSync(policyPath), 'init-policy wrote .pasteshield.json');
  var policySanOut = childProcess.execFileSync(
    process.execPath,
    ['--require', mockPreload, CLI_PATH, 'sanitize', '--policy', policyPath, '--license', 'GUMROAD-MOCK-PRO-KEY-7777', '--quiet'],
    { input: 'TICKET=SEC-ABCD1234EFGH5678', encoding: 'utf8' }
  );
  assert.strictEqual(policySanOut.trim(), 'TICKET=<INTERNAL_TICKET_TOKEN_1>', 'CLI --policy applies customPatterns from .pasteshield.json');

  console.log('All PasteShield Core, CLI & MCP Gumroad Pro tests passed (0 dependencies).');
} finally {
  cleanup();
}
