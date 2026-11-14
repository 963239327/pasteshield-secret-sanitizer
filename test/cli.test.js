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

  console.log('All PasteShield Core & CLI tests passed (0 dependencies, 100% offline).');
} finally {
  cleanup();
}
