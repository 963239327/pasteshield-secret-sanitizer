#!/usr/bin/env node
/**
 * PasteShield MCP Server (Model Context Protocol — Zero-Dependency stdio JSON-RPC 2.0)
 * Exposes 100% local, zero-network secret sanitization, restoration, and audit tools
 * for Claude Desktop, Cursor, Windsurf, VS Code Copilot, and Zed.
 *
 * Run with zero install via GitHub npx:
 *   npx -y github:963239327/pasteshield-secret-sanitizer --mcp
 */
'use strict';

var fs = require('fs');
var path = require('path');
var PasteShieldCore = require('../sanitizer-core');

var sessionVault = PasteShieldCore.createVault(process.env.PASTESHIELD_LICENSE || '');

var TOOLS = [
  {
    name: 'sanitize_snippet',
    description: 'Scrub API keys, JWTs, DB URIs, cloud credentials, PEM private keys, and internal IPs into deterministic reversible placeholders (<OPENAI_KEY_1>, <DB_URI_1>) stored strictly in local process RAM.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Raw code, .env snippet, or stack trace to sanitize locally.' },
        redactEmails: { type: 'boolean', description: 'Redact email addresses (default true).' },
        redactInternalIps: { type: 'boolean', description: 'Redact RFC1918/CGNAT internal IPv4 addresses (default true).' }
      },
      required: ['text']
    }
  },
  {
    name: 'restore_snippet',
    description: 'Restore deterministic <CATEGORY_N> placeholders back to their original local secret values from the in-memory PasteShield session vault.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text or refactored code containing <CATEGORY_N> placeholders.' }
      },
      required: ['text']
    }
  },
  {
    name: 'audit_workspace_secrets',
    description: 'Scan a local file or directory for exposed credentials and return ONLY masked previews (never raw secret values).',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: { type: 'string', description: 'Local file or directory path to audit (defaults to current working directory).' }
      }
    }
  }
];

var SKIP_DIRS = { '.git': true, 'node_modules': true, 'dist': true, 'build': true, '.next': true, 'vendor': true };

function collectFiles(target, acc) {
  if (!fs.existsSync(target) || acc.length >= 200) return;
  var st = fs.statSync(target);
  if (st.isFile()) {
    if (st.size <= 512 * 1024) acc.push(target);
    return;
  }
  if (st.isDirectory()) {
    var entries = fs.readdirSync(target);
    for (var i = 0; i < entries.length; i++) {
      if (SKIP_DIRS[entries[i]]) continue;
      collectFiles(path.join(target, entries[i]), acc);
      if (acc.length >= 200) break;
    }
  }
}

function handleToolCall(params) {
  var name = params && params.name;
  var args = (params && params.arguments) || {};

  if (name === 'sanitize_snippet') {
    var res = sessionVault.sanitize(String(args.text || ''), {
      redactEmails: args.redactEmails !== false,
      redactInternalIps: args.redactInternalIps !== false
    });
    var payload = {
      sanitizedText: res.sanitizedText,
      redactionCount: res.totalRedactions,
      activeVaultPlaceholders: sessionVault.size(),
      categoriesDetected: res.summary
    };
    return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
  }

  if (name === 'restore_snippet') {
    var r = sessionVault.restore(String(args.text || ''));
    var out = {
      restoredText: r.restoredText,
      restoredCount: r.restoredCount,
      unresolvedPlaceholders: r.unresolvedPlaceholders || []
    };
    return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
  }

  if (name === 'audit_workspace_secrets') {
    var rootTarget = path.resolve(String(args.targetPath || process.cwd()));
    var files = [];
    collectFiles(rootTarget, files);
    var tempVault = PasteShieldCore.createVault();
    var findings = [];
    for (var i = 0; i < files.length; i++) {
      var content = '';
      try { content = fs.readFileSync(files[i], 'utf8'); } catch (_e) { continue; }
      if (content.indexOf('\u0000') !== -1) continue;
      tempVault.clear();
      var scan = tempVault.sanitize(content, { redactEmails: false, redactInternalIps: false });
      if (scan.totalRedactions > 0) {
        var ents = tempVault.entries();
        for (var j = 0; j < ents.length; j++) {
          findings.push({
            file: path.relative(rootTarget, files[i]) || path.basename(files[i]),
            category: ents[j].category,
            severity: ents[j].severity,
            maskedPreview: ents[j].maskedPreview,
            placeholder: ents[j].placeholder
          });
        }
      }
    }
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          scannedFiles: files.length,
          findingsCount: findings.length,
          findings: findings.slice(0, 100),
          proUpgradeNote: 'Get PasteShield VS Code extension or Pro custom corporate domain rules at https://963239327.github.io/craftleaf-studio/extensions/pasteshield/'
        }, null, 2)
      }]
    };
  }

  throw new Error('Unknown tool: ' + name);
}

var useContentLengthFraming = false;

function sendMessage(msg) {
  var json = JSON.stringify(msg);
  if (useContentLengthFraming) {
    var byteLen = Buffer.byteLength(json, 'utf8');
    process.stdout.write('Content-Length: ' + byteLen + '\r\n\r\n' + json);
  } else {
    process.stdout.write(json + '\n');
  }
}

function dispatchRpc(req) {
  if (!req || typeof req !== 'object') return;
  var id = req.id;
  var method = req.method;

  // Notifications have no id and require no response
  if (id === undefined || id === null) return;

  try {
    if (method === 'initialize') {
      var clientProto = (req.params && req.params.protocolVersion) || '2024-11-05';
      sendMessage({
        jsonrpc: '2.0',
        id: id,
        result: {
          protocolVersion: clientProto,
          capabilities: { tools: {} },
          serverInfo: {
            name: 'pasteshield-mcp',
            version: PasteShieldCore.VERSION
          }
        }
      });
    } else if (method === 'ping') {
      sendMessage({ jsonrpc: '2.0', id: id, result: {} });
    } else if (method === 'tools/list') {
      sendMessage({ jsonrpc: '2.0', id: id, result: { tools: TOOLS } });
    } else if (method === 'tools/call') {
      var res = handleToolCall(req.params || {});
      sendMessage({ jsonrpc: '2.0', id: id, result: res });
    } else {
      sendMessage({
        jsonrpc: '2.0',
        id: id,
        error: { code: -32601, message: 'Method not found: ' + method }
      });
    }
  } catch (err) {
    sendMessage({
      jsonrpc: '2.0',
      id: id,
      error: { code: -32603, message: err && err.message ? err.message : String(err) }
    });
  }
}

function startMcpServer() {
  var buf = Buffer.alloc(0);
  process.stdin.on('data', function (chunk) {
    buf = Buffer.concat([buf, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    while (buf.length > 0) {
      var headerProbe = buf.slice(0, Math.min(buf.length, 64)).toString('utf8');
      if (/^Content-Length:/i.test(headerProbe)) {
        useContentLengthFraming = true;
        var sepIdx = buf.indexOf('\r\n\r\n');
        if (sepIdx === -1) return;
        var headerStr = buf.slice(0, sepIdx).toString('utf8');
        var m = headerStr.match(/Content-Length:\s*(\d+)/i);
        var bodyLen = m ? parseInt(m[1], 10) : 0;
        var totalNeeded = sepIdx + 4 + bodyLen;
        if (buf.length < totalNeeded) return;
        var bodyStr = buf.slice(sepIdx + 4, totalNeeded).toString('utf8');
        buf = buf.slice(totalNeeded);
        try { dispatchRpc(JSON.parse(bodyStr)); } catch (_e) {}
      } else {
        var nlIdx = buf.indexOf('\n');
        if (nlIdx === -1) return;
        var line = buf.slice(0, nlIdx).toString('utf8').trim();
        buf = buf.slice(nlIdx + 1);
        if (line) {
          try { dispatchRpc(JSON.parse(line)); } catch (_e) {}
        }
      }
    }
  });
}

if (require.main === module) {
  startMcpServer();
}

module.exports = { startMcpServer: startMcpServer, TOOLS: TOOLS };
