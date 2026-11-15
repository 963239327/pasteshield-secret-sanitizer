#!/usr/bin/env node
/**
 * PasteShield CLI — Zero-Dependency Reversible AI Prompt & Clipboard Secret Sanitizer
 * Runnable directly via Node.js (`node bin/pasteshield-cli.js`) or Bun (`bun bin/pasteshield-cli.js`).
 *
 * 100% offline processing. Zero npm runtime dependencies. Zero network calls.
 */
'use strict';

var fs = require('fs');
var path = require('path');
var childProcess = require('child_process');
var PasteShieldCore = require('../sanitizer-core');

var PLAYGROUND_URL = 'https://963239327.github.io/craftleaf-studio/extensions/pasteshield/';
var PRO_URL = 'https://stardustdemo.gumroad.com/l/pasteshield-pro';
var VSIX_RELEASE_URL = 'https://github.com/963239327/pasteshield-secret-sanitizer/releases/latest/download/pasteshield-ai-secret-sanitizer-1.1.0.vsix';

var SKIP_DIRS = {
  '.git': true,
  'node_modules': true,
  'dist': true,
  'build': true,
  '.next': true,
  'coverage': true,
  'vendor': true
};

function printHelp() {
  var help = [
    'PasteShield v' + PasteShieldCore.VERSION + ' — Reversible Offline AI Prompt & Clipboard Secret Sanitizer',
    '',
    'USAGE:',
    '  pasteshield --mcp                 Start local stdio Model Context Protocol (MCP) server',
    '  pasteshield demo',
    '  pasteshield sanitize [file] [--vault <vault.json>] [--quiet] [--json]',
    '  pasteshield restore  [file] --vault <vault.json> [--quiet]',
    '  pasteshield scan     [paths...] [--git-diff] [--license <KEY>]',
    '  pasteshield pack     <files...> --license <KEY> [--vault <vault.json>]',
    '',
    'STDIN / PIPE EXAMPLES:',
    '  cat .env | node bin/pasteshield-cli.js sanitize --vault .pasteshield-vault.json',
    '  pbpaste  | node bin/pasteshield-cli.js sanitize --vault .pasteshield-vault.json | pbcopy',
    '  pbpaste  | node bin/pasteshield-cli.js restore  --vault .pasteshield-vault.json | pbcopy',
    '',
    'OPTIONS:',
    '  --vault <path>       Save/load local bidirectional placeholder map (0600 permissions)',
    '  --no-emails          Keep email addresses unredacted',
    '  --no-ips             Keep RFC1918 / Tailscale private IPv4s unredacted',
    '  --domain <suffix>    [Pro] Redact internal company domains (e.g. corp.acme.internal)',
    '  --pattern <RULE>     [Pro] Custom regex rule formatted as NAME::regex',
    '  --license <KEY>      [Pro] Gumroad License Key for PasteShield Pro or All-Access (or $PASTESHIELD_LICENSE)',
    '  --git-diff           Scan uncommitted `git diff` additions for accidental secret leaks',
    '  --json               Emit structured JSON summary (sanitize / scan)',
    '  -q, --quiet          Suppress stderr status summary',
    '  -v, --version        Print version',
    '  -h, --help           Show this help message',
    '',
    'LINKS:',
    '  VS Code & Cursor Extension (.vsix): ' + VSIX_RELEASE_URL,
    '  Live Browser Playground:            ' + PLAYGROUND_URL,
    '  Unlock PasteShield Pro ($9):        ' + PRO_URL
  ].join('\n');
  process.stdout.write(help + '\n');
}

function parseArgs(argv) {
  var opts = {
    command: '',
    positionals: [],
    vaultPath: '',
    redactEmails: true,
    redactInternalIps: true,
    companyDomains: [],
    customPatterns: [],
    licenseKey: process.env.PASTESHIELD_LICENSE || '',
    gitDiff: false,
    json: false,
    quiet: false,
    help: false,
    version: false
  };

  for (var i = 0; i < argv.length; i++) {
    var arg = argv[i];
    if (arg === '--mcp' || arg === 'mcp') {
      opts.command = 'mcp';
    } else if (arg === '-h' || arg === '--help') {
      opts.help = true;
    } else if (arg === '-v' || arg === '--version') {
      opts.version = true;
    } else if (arg === '-q' || arg === '--quiet') {
      opts.quiet = true;
    } else if (arg === '--json') {
      opts.json = true;
    } else if (arg === '--no-emails') {
      opts.redactEmails = false;
    } else if (arg === '--no-ips') {
      opts.redactInternalIps = false;
    } else if (arg === '--git-diff') {
      opts.gitDiff = true;
    } else if (arg === '--vault' && i + 1 < argv.length) {
      opts.vaultPath = argv[++i];
    } else if (arg === '--domain' && i + 1 < argv.length) {
      opts.companyDomains.push(argv[++i]);
    } else if (arg === '--pattern' && i + 1 < argv.length) {
      opts.customPatterns.push(argv[++i]);
    } else if (arg === '--license' && i + 1 < argv.length) {
      opts.licenseKey = argv[++i];
    } else if (!opts.command && arg.charAt(0) !== '-') {
      opts.command = arg;
    } else {
      opts.positionals.push(arg);
    }
  }
  return opts;
}

function readStdinSync() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch (_e) {
    return '';
  }
}

function loadVaultFromFile(vault, vaultPath) {
  if (!vaultPath || !fs.existsSync(vaultPath)) {
    return;
  }
  var raw = JSON.parse(fs.readFileSync(vaultPath, 'utf8'));
  if (raw && typeof raw === 'object') {
    if (raw.secretToToken) Object.assign(vault.secretToToken, raw.secretToToken);
    if (raw.tokenToSecret) Object.assign(vault.tokenToSecret, raw.tokenToSecret);
    if (raw.tokenMeta) Object.assign(vault.tokenMeta, raw.tokenMeta);
    if (raw.categoryCounters) Object.assign(vault.categoryCounters, raw.categoryCounters);
  }
}

function saveVaultToFile(vault, vaultPath) {
  if (!vaultPath) return;
  var payload = {
    version: PasteShieldCore.VERSION,
    updatedAt: new Date().toISOString(),
    warning: 'LOCAL SECRET VAULT — DO NOT COMMIT TO GIT',
    secretToToken: vault.secretToToken,
    tokenToSecret: vault.tokenToSecret,
    tokenMeta: vault.tokenMeta,
    categoryCounters: vault.categoryCounters
  };
  fs.writeFileSync(vaultPath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 });
}

function collectFilesRecursive(targetPath, out, maxFiles) {
  if (out.length >= maxFiles) return;
  var stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (_e) {
    return;
  }
  if (stat.isFile()) {
    if (stat.size <= 1024 * 1024) {
      out.push(targetPath);
    }
    return;
  }
  if (stat.isDirectory()) {
    var base = path.basename(targetPath);
    if (SKIP_DIRS[base]) return;
    var entries = fs.readdirSync(targetPath);
    for (var i = 0; i < entries.length; i++) {
      collectFilesRecursive(path.join(targetPath, entries[i]), out, maxFiles);
      if (out.length >= maxFiles) break;
    }
  }
}

function runDemo() {
  var vault = PasteShieldCore.createVault();
  var sampleInput = [
    '# Production Billing Service (.env)',
    'OPENAI_API_KEY=sk-proj-EXAMPLE000000000000000000000001',
    'GITHUB_DEPLOY_TOKEN=ghp_EXAMPLE00000000000000000000000001',
    'DATABASE_URL="postgresql://billing_app:DemoPass!99@10.24.18.42:5432/prod_ledger"',
    'ONCALL_ALERT_EMAIL=secops@acme-payments.example'
  ].join('\n');

  var san = vault.sanitize(sampleInput);
  var aiReply = [
    '// Refactored TypeScript config generated safely by ChatGPT / Claude:',
    'export const runtimeConfig = {',
    '  llmApiKey: "' + (san.placeholdersUsed[1] || '<OPENAI_KEY_1>') + '",',
    '  dbConnection: "' + (san.placeholdersUsed[0] || '<DB_URI_1>') + '",',
    '  deployToken: "' + (san.placeholdersUsed[2] || '<GITHUB_TOKEN_1>') + '",',
    '  alertRecipient: "' + (san.placeholdersUsed[3] || '<EMAIL_1>') + '"',
    '};'
  ].join('\n');

  var restored = vault.restore(aiReply);

  var lines = [
    '======================================================================',
    '  PasteShield v' + PasteShieldCore.VERSION + ' — 100% Offline Reversible Sanitization Demo',
    '======================================================================',
    '',
    '[1] RAW LOCAL SNIPPET (NEVER SENT TO CLOUD LLMs):',
    '----------------------------------------------------------------------',
    sampleInput,
    '',
    '[2] SANITIZED PROMPT SAFE FOR CHATGPT / CLAUDE / CURSOR (' + san.totalRedactions + ' redacted):',
    '----------------------------------------------------------------------',
    san.sanitizedText,
    '',
    '[3] SIMULATED AI CODE REPLY (PRESERVES SEMANTIC PLACEHOLDERS):',
    '----------------------------------------------------------------------',
    aiReply,
    '',
    '[4] 1-CLICK LOCAL RESTORATION (' + restored.restoredCount + ' credentials restored in <1ms):',
    '----------------------------------------------------------------------',
    restored.restoredText,
    '',
    'Install for VS Code / Cursor (.vsix): ' + VSIX_RELEASE_URL,
    'Interactive Browser Playground:       ' + PLAYGROUND_URL
  ];
  process.stdout.write(lines.join('\n') + '\n');
  return 0;
}

async function prepareVault(opts) {
  var vault = PasteShieldCore.createVault();
  if (opts && opts.licenseKey && String(opts.licenseKey).trim()) {
    var check = await vault.verifyGumroadLicense(opts.licenseKey);
    if (!check.valid && !opts.quiet) {
      process.stderr.write('[PasteShield Pro] Gumroad license verification failed (' + check.reason + '). Continuing in Free tier.\n');
    }
  }
  return vault;
}

async function runSanitize(opts) {
  var inputText = opts.positionals.length > 0
    ? fs.readFileSync(opts.positionals[0], 'utf8')
    : readStdinSync();

  var vault = await prepareVault(opts);
  loadVaultFromFile(vault, opts.vaultPath);

  var res = vault.sanitize(inputText, {
    redactEmails: opts.redactEmails,
    redactInternalIps: opts.redactInternalIps,
    companyDomains: opts.companyDomains,
    customPatterns: opts.customPatterns
  });

  if (opts.vaultPath) {
    saveVaultToFile(vault, opts.vaultPath);
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + '\n');
  } else {
    process.stdout.write(res.sanitizedText);
  }

  if (!opts.quiet) {
    process.stderr.write(
      '[PasteShield] Redacted ' + res.totalRedactions + ' secret(s) across ' +
      Object.keys(res.countsByCategory).length + ' detector(s)' +
      (opts.vaultPath ? ' -> vault saved to ' + opts.vaultPath : '') + '\n'
    );
    if (res.proGatedCustomRules > 0) {
      process.stderr.write(
        '[PasteShield Pro] ' + res.proGatedCustomRules +
        ' custom domain/regex rule(s) skipped (pass --license <GUMROAD_KEY> or $PASTESHIELD_LICENSE: ' + PRO_URL + ')\n'
      );
    }
  }
  return 0;
}

function runRestore(opts) {
  if (!opts.vaultPath) {
    process.stderr.write('[PasteShield] Error: `restore` requires `--vault <vault.json>` created during `sanitize`.\n');
    return 1;
  }
  if (!fs.existsSync(opts.vaultPath)) {
    process.stderr.write('[PasteShield] Error: Vault file not found: ' + opts.vaultPath + '\n');
    return 1;
  }
  var inputText = opts.positionals.length > 0
    ? fs.readFileSync(opts.positionals[0], 'utf8')
    : readStdinSync();

  var vault = PasteShieldCore.createVault();
  loadVaultFromFile(vault, opts.vaultPath);

  var res = vault.restore(inputText);
  process.stdout.write(res.restoredText);

  if (!opts.quiet) {
    process.stderr.write(
      '[PasteShield] Restored ' + res.restoredCount + ' placeholder(s)' +
      (res.unresolvedPlaceholders.length
        ? ' (' + res.unresolvedPlaceholders.length + ' unresolved: ' + res.unresolvedPlaceholders.join(', ') + ')'
        : '') + '\n'
    );
  }
  return 0;
}

async function runScan(opts) {
  var targets = [];
  if (opts.gitDiff) {
    var diffOut = childProcess.execSync('git --no-pager diff HEAD', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    targets.push({ path: 'git-diff-HEAD', content: diffOut });
  } else {
    var roots = opts.positionals.length > 0 ? opts.positionals : ['.'];
    var filePaths = [];
    for (var r = 0; r < roots.length; r++) {
      collectFilesRecursive(roots[r], filePaths, 250);
    }
    for (var f = 0; f < filePaths.length; f++) {
      var fp = filePaths[f];
      if (path.basename(fp).indexOf('.pasteshield-vault') === 0) continue;
      try {
        var content = fs.readFileSync(fp, 'utf8');
        if (content.indexOf('\u0000') === -1) {
          targets.push({ path: fp, content: content });
        }
      } catch (_e) {}
    }
  }

  var vault = await prepareVault(opts);
  if (vault.isPro()) {
    var proReport = vault.buildSecretAuditReport(targets, {
      redactEmails: opts.redactEmails,
      redactInternalIps: opts.redactInternalIps,
      companyDomains: opts.companyDomains,
      customPatterns: opts.customPatterns,
      diffAddedOnly: opts.gitDiff
    });
    if (opts.json) {
      process.stdout.write(JSON.stringify(proReport, null, 2) + '\n');
    } else {
      process.stdout.write(proReport.markdown);
    }
    return proReport.findingsCount > 0 ? 2 : 0;
  }

  // Free community scanner: fast masked terminal summary using built-in detectors
  var findings = [];
  var scanVault = PasteShieldCore.createVault();
  for (var i = 0; i < targets.length; i++) {
    var item = targets[i];
    var lines = item.content.split(/\r?\n/);
    for (var lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      var rawLine = lines[lineIdx];
      if (!rawLine || rawLine.length > 4000) continue;
      if (opts.gitDiff && rawLine.charAt(0) === '-' && rawLine.slice(0, 3) !== '---') continue;
      var lineRes = scanVault.sanitize(rawLine, {
        redactEmails: opts.redactEmails,
        redactInternalIps: opts.redactInternalIps
      });
      if (lineRes.totalRedactions > 0) {
        for (var p = 0; p < lineRes.placeholdersUsed.length; p++) {
          var ph = lineRes.placeholdersUsed[p];
          var rawVal = scanVault.tokenToSecret[ph] || '';
          var meta = scanVault.tokenMeta[ph] || {};
          findings.push({
            path: item.path,
            line: lineIdx + 1,
            category: meta.category || 'SECRET',
            severity: meta.severity || 'HIGH',
            placeholder: ph,
            maskedPreview: PasteShieldCore.maskSecretPreview(rawVal)
          });
        }
      }
    }
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      scannedCount: targets.length,
      findingsCount: findings.length,
      findings: findings
    }, null, 2) + '\n');
    return findings.length > 0 ? 2 : 0;
  }

  process.stdout.write('PasteShield Local Secret Scan — ' + targets.length + ' target(s) inspected\n');
  if (findings.length === 0) {
    process.stdout.write('Status: CLEAN (0 hardcoded secrets detected)\n');
    return 0;
  }

  process.stdout.write('Status: FOUND ' + findings.length + ' potential secret exposure(s):\n');
  for (var k = 0; k < findings.length; k++) {
    var fd = findings[k];
    process.stdout.write(
      '  [' + fd.severity + '] ' + fd.path + ':' + fd.line +
      '  ' + fd.category + ' -> ' + fd.placeholder + ' (' + fd.maskedPreview + ')\n'
    );
  }
  process.stdout.write(
    '\nTip: Unlock full Markdown Audit Reports + Custom Company Domain/Regex rules with PasteShield Pro ($9): ' + PRO_URL + '\n'
  );
  return 2;
}

async function runPack(opts) {
  if (opts.positionals.length === 0) {
    process.stderr.write('[PasteShield] Error: `pack` requires one or more file paths.\n');
    return 1;
  }
  var vault = await prepareVault(opts);
  if (!vault.isPro()) {
    process.stderr.write(
      '[PasteShield Pro] Multi-File Sanitized AI Markdown Context Pack requires a valid Gumroad PasteShield Pro or CraftLeaf All-Access license key (`--license <KEY>` or `$PASTESHIELD_LICENSE`).\n' +
      'Get lifetime license ($9 one-time): ' + PRO_URL + '\n'
    );
    return 1;
  }
  loadVaultFromFile(vault, opts.vaultPath);

  var files = opts.positionals.map(function (fp) {
    return {
      path: fp,
      content: fs.readFileSync(fp, 'utf8')
    };
  });

  var res = vault.buildContextPack(files, {
    redactEmails: opts.redactEmails,
    redactInternalIps: opts.redactInternalIps,
    companyDomains: opts.companyDomains,
    customPatterns: opts.customPatterns
  });

  if (opts.vaultPath) {
    saveVaultToFile(vault, opts.vaultPath);
  }
  process.stdout.write(res.markdown);
  return 0;
}

async function main() {
  var opts = parseArgs(process.argv.slice(2));
  if (opts.version) {
    process.stdout.write(PasteShieldCore.VERSION + '\n');
    process.exit(0);
  }
  if (opts.help || !opts.command) {
    printHelp();
    process.exit(0);
  }

  var code = 0;
  if (opts.command === 'mcp') {
    require('./pasteshield-mcp').startMcpServer();
    return;
  } else if (opts.command === 'demo') {
    code = runDemo();
  } else if (opts.command === 'sanitize') {
    code = await runSanitize(opts);
  } else if (opts.command === 'restore') {
    code = runRestore(opts);
  } else if (opts.command === 'scan') {
    code = await runScan(opts);
  } else if (opts.command === 'pack') {
    code = await runPack(opts);
  } else {
    process.stderr.write('[PasteShield] Unknown command: ' + opts.command + '\n\n');
    printHelp();
    code = 1;
  }
  process.exit(code);
}

main().catch(function (err) {
  process.stderr.write('[PasteShield] Fatal error: ' + (err && err.message ? err.message : String(err)) + '\n');
  process.exit(1);
});
