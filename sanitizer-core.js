/**
 * PasteShield Core — Reversible AI Prompt Secret Sanitizer & Offline License Engine
 * Zero-dependency universal module compatible with:
 *   - VS Code / Cursor Node.js Extension Host (CommonJS)
 *   - macOS JavaScriptCore (`jsc`) CLI unit tests
 *   - Browser static live playground (`window.PasteShieldCore`)
 *
 * 100% local in-memory processing. Zero network calls, zero telemetry.
 */
(function (root) {
  'use strict';

  var LICENSE_SALT = 'StudioCraft-2026-v1';
  var ALLOWED_PREFIXES = ['SHIELDPRO', 'STUDIOALL'];
  var PLACEHOLDER_EXACT_RE = /^<[A-Z][A-Z0-9_]{1,40}_[1-9]\d*>$/;
  var PLACEHOLDER_ANY_RE = /<([A-Z][A-Z0-9_]{1,40})_([1-9]\d*)>/g;

  var IGNORED_ENV_VALUES = {
    'true': true,
    'false': true,
    'null': true,
    'none': true,
    'undefined': true,
    'changeme': true,
    'password': true,
    'secret': true,
    'example': true,
    'redacted': true,
    'your_api_key': true,
    'your_api_key_here': true,
    'your_secret_here': true,
    'replace_me': true,
    'todo': true
  };

  var CATEGORY_SEVERITY = {
    PRIVATE_KEY_BLOCK: 'CRITICAL',
    AZURE_CONN_STR: 'CRITICAL',
    DB_URI: 'CRITICAL',
    OPENAI_KEY: 'CRITICAL',
    AWS_ACCESS_KEY: 'CRITICAL',
    GITHUB_TOKEN: 'CRITICAL',
    BEARER_JWT: 'HIGH',
    ENV_SECRET: 'HIGH',
    COMPANY_DOMAIN: 'HIGH',
    INTERNAL_IP: 'MEDIUM',
    EMAIL: 'MEDIUM'
  };

  /**
   * Exact FNV-1a 32-bit hash formatted as 6 uppercase hex characters,
   * matching shared/monetization-sdk.js.
   */
  function fnv1aHex6(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ('00000000' + h.toString(16).toUpperCase()).slice(-8).slice(0, 6);
  }

  function normalizeLicenseKey(raw) {
    return String(raw || '').trim().toUpperCase().replace(/\s+/g, '');
  }

  /**
   * Offline cryptographic checksum verifier for PasteShield Pro keys:
   * Accepts SHIELDPRO-XXXX-XXXX-XXXXXX or STUDIOALL-XXXX-XXXX-XXXXXX.
   */
  function verifyLicenseKey(rawKey, customPrefixes) {
    var key = normalizeLicenseKey(rawKey);
    if (!key) {
      return { valid: false, reason: 'empty' };
    }
    var parts = key.split('-');
    if (parts.length !== 4) {
      return { valid: false, reason: 'format' };
    }
    var prefix = parts[0];
    var p1 = parts[1];
    var p2 = parts[2];
    var sig = parts[3];

    var validPrefixes = Array.isArray(customPrefixes) && customPrefixes.length
      ? customPrefixes.concat(['STUDIOALL'])
      : ALLOWED_PREFIXES;

    if (validPrefixes.indexOf(prefix) === -1) {
      return { valid: false, reason: 'prefix' };
    }
    if (!/^[A-Z2-9]{4}$/.test(p1) || !/^[A-Z2-9]{4}$/.test(p2) || !/^[0-9A-F]{6}$/.test(sig)) {
      return { valid: false, reason: 'charset' };
    }
    var expected = fnv1aHex6(prefix + '-' + p1 + '-' + p2 + '::' + LICENSE_SALT);
    if (sig !== expected) {
      return { valid: false, reason: 'checksum' };
    }
    return {
      valid: true,
      mode: 'offline',
      prefix: prefix,
      tier: prefix === 'STUDIOALL' ? 'all-access' : 'pro',
      key: key
    };
  }

  function sanitizeCategoryName(rawName, fallback) {
    var cleaned = String(rawName || '')
      .trim()
      .toUpperCase()
      .replace(/[^A-Z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '');
    if (!cleaned || !/^[A-Z]/.test(cleaned)) {
      cleaned = fallback || 'CUSTOM_SECRET';
    }
    return cleaned.slice(0, 32);
  }

  function escapeRegex(literal) {
    return String(literal).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function hasExistingPlaceholder(str) {
    if (!str) return false;
    PLACEHOLDER_ANY_RE.lastIndex = 0;
    return PLACEHOLDER_ANY_RE.test(str);
  }

  function isSkippableEnvValue(val) {
    if (!val) return true;
    var trimmed = String(val).trim();
    if (trimmed.length < 6) return true;
    if (PLACEHOLDER_EXACT_RE.test(trimmed) || hasExistingPlaceholder(trimmed)) return true;
    if (trimmed.charAt(0) === '$') return true;
    if (/^\{\{.*\}\}$/.test(trimmed) || /^<.*>$/.test(trimmed)) return true;
    if (/^(?:https?:\/\/|\/|\.\/|\.\.\/)/.test(trimmed) && !/:\/\/[^/\s]+:[^/\s]+@/.test(trimmed)) {
      return true;
    }
    var lower = trimmed.toLowerCase();
    if (IGNORED_ENV_VALUES[lower]) return true;
    return false;
  }

  function maskSecretPreview(raw) {
    var s = String(raw || '');
    if (s.indexOf('\n') !== -1) {
      var firstLine = s.split(/\r?\n/)[0];
      return firstLine.slice(0, 22) + ' … [REDACTED BLOCK]';
    }
    if (s.length <= 8) {
      return s.slice(0, 2) + '••••••';
    }
    return s.slice(0, 4) + '••••••••' + s.slice(-3);
  }

  /**
   * Bidirectional in-memory session vault mapping real secrets <-> deterministic placeholders.
   */
  function SessionVault(initialLicenseKey) {
    this.secretToToken = Object.create(null);
    this.tokenToSecret = Object.create(null);
    this.tokenMeta = Object.create(null);
    this.categoryCounters = Object.create(null);
    this.licenseStatus = { valid: false, reason: 'empty' };
    if (initialLicenseKey) {
      this.activateLicense(initialLicenseKey);
    }
  }

  SessionVault.prototype.activateLicense = function (rawKey) {
    var check = verifyLicenseKey(rawKey);
    this.licenseStatus = check;
    return check;
  };

  SessionVault.prototype.deactivateLicense = function () {
    this.licenseStatus = { valid: false, reason: 'deactivated' };
  };

  SessionVault.prototype.isPro = function (overrideLicenseKey) {
    if (overrideLicenseKey !== undefined && overrideLicenseKey !== null && overrideLicenseKey !== '') {
      return verifyLicenseKey(overrideLicenseKey).valid;
    }
    return Boolean(this.licenseStatus && this.licenseStatus.valid);
  };

  SessionVault.prototype.clear = function () {
    this.secretToToken = Object.create(null);
    this.tokenToSecret = Object.create(null);
    this.tokenMeta = Object.create(null);
    this.categoryCounters = Object.create(null);
  };

  SessionVault.prototype.size = function () {
    return Object.keys(this.tokenToSecret).length;
  };

  SessionVault.prototype.entries = function () {
    var self = this;
    return Object.keys(this.tokenToSecret).map(function (token) {
      var secret = self.tokenToSecret[token];
      var meta = self.tokenMeta[token] || {};
      return {
        placeholder: token,
        category: meta.category || 'SECRET',
        severity: meta.severity || CATEGORY_SEVERITY[meta.category] || 'HIGH',
        preview: maskSecretPreview(secret),
        length: secret.length
      };
    });
  };

  SessionVault.prototype.intern = function (category, rawSecret) {
    var cat = sanitizeCategoryName(category, 'SECRET');
    var compositeKey = cat + '\u0000' + rawSecret;
    if (this.secretToToken[compositeKey]) {
      return this.secretToToken[compositeKey];
    }
    // Ensure we never collide with any existing token number in this category
    var nextIndex = (this.categoryCounters[cat] || 0) + 1;
    var candidate = '<' + cat + '_' + nextIndex + '>';
    while (this.tokenToSecret[candidate] && this.tokenToSecret[candidate] !== rawSecret) {
      nextIndex += 1;
      candidate = '<' + cat + '_' + nextIndex + '>';
    }
    this.categoryCounters[cat] = nextIndex;
    this.secretToToken[compositeKey] = candidate;
    this.tokenToSecret[candidate] = rawSecret;
    this.tokenMeta[candidate] = {
      category: cat,
      severity: CATEGORY_SEVERITY[cat] || 'HIGH'
    };
    return candidate;
  };

  function compileCustomRules(options) {
    var compiled = [];
    var customPatterns = (options && Array.isArray(options.customPatterns)) ? options.customPatterns : [];
    var companyDomains = (options && Array.isArray(options.companyDomains)) ? options.companyDomains : [];

    for (var i = 0; i < companyDomains.length; i++) {
      var rawDom = String(companyDomains[i] || '').trim().replace(/^\*\./, '');
      if (!rawDom) continue;
      try {
        var domRegex = new RegExp('(?:[A-Za-z0-9-]+\\.)*' + escapeRegex(rawDom) + '\\b', 'gi');
        compiled.push({
          category: 'COMPANY_DOMAIN',
          regex: domRegex
        });
      } catch (_e) {}
    }

    for (var j = 0; j < customPatterns.length; j++) {
      var item = customPatterns[j];
      if (!item) continue;
      if (typeof item === 'string') {
        var strItem = item.trim();
        if (!strItem) continue;
        var sepIdx = strItem.indexOf('::');
        if (sepIdx > 0) {
          var label = sanitizeCategoryName(strItem.slice(0, sepIdx), 'CUSTOM_RULE');
          var patStr = strItem.slice(sepIdx + 2);
          try {
            compiled.push({ category: label, regex: new RegExp(patStr, 'g') });
          } catch (_e2) {}
        } else {
          var cleanDomain = strItem.replace(/^\*\./, '');
          try {
            compiled.push({
              category: 'COMPANY_DOMAIN',
              regex: new RegExp('(?:[A-Za-z0-9-]+\\.)*' + escapeRegex(cleanDomain) + '\\b', 'gi')
            });
          } catch (_e3) {}
        }
      } else if (typeof item === 'object' && item.pattern) {
        var catName = sanitizeCategoryName(item.name || item.category || 'CUSTOM_RULE', 'CUSTOM_RULE');
        var rawFlags = String(item.flags || 'g').replace(/[^gimsuy]/g, '');
        if (rawFlags.indexOf('g') === -1) rawFlags += 'g';
        try {
          compiled.push({
            category: catName,
            regex: new RegExp(String(item.pattern), rawFlags)
          });
        } catch (_e4) {}
      }
    }
    return compiled;
  }

  /**
   * Sanitizes input text, storing secrets in the SessionVault and returning
   * redacted text + structured telemetry counts (never leaves the device).
   */
  SessionVault.prototype.sanitize = function (inputText, options) {
    options = options || {};
    var text = String(inputText == null ? '' : inputText);
    if (!text) {
      return {
        sanitizedText: '',
        changed: false,
        totalRedactions: 0,
        countsByCategory: {},
        placeholdersUsed: [],
        proActive: this.isPro(options.licenseKey),
        proGatedCustomRules: 0
      };
    }

    var self = this;
    var countsByCategory = Object.create(null);
    var placeholdersSet = Object.create(null);
    var totalRedactions = 0;

    function recordMatch(category, secretValue) {
      var token = self.intern(category, secretValue);
      countsByCategory[category] = (countsByCategory[category] || 0) + 1;
      placeholdersSet[token] = true;
      totalRedactions += 1;
      return token;
    }

    function applyWholeMatch(category, regex) {
      text = text.replace(regex, function (fullMatch) {
        if (!fullMatch || hasExistingPlaceholder(fullMatch)) {
          return fullMatch;
        }
        return recordMatch(category, fullMatch);
      });
    }

    // 1. Multi-line PEM / OpenSSH / PGP Private Key Blocks
    applyWholeMatch(
      'PRIVATE_KEY_BLOCK',
      /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g
    );

    // 2. Azure Storage / ServiceBus / Cosmos / IoT / SQL Connection Strings
    applyWholeMatch(
      'AZURE_CONN_STR',
      /(?:DefaultEndpointsProtocol=https?;AccountName=[^;\s"']+;AccountKey=[A-Za-z0-9+/=]{16,}(?:;[^\s"'`<>]+)?|Endpoint=sb:\/\/[^;\s"']+;SharedAccessKeyName=[^;\s"']+;SharedAccessKey=[A-Za-z0-9+/=]{12,}(?:;[^\s"'`<>]+)?|AccountEndpoint=https:\/\/[^;\s"']+;AccountKey=[A-Za-z0-9+/=]{16,};?|HostName=[^;\s"']+\.azure-devices\.net;(?:DeviceId=[^;\s"']+;)?SharedAccessKey(?:Name=[^;\s"']+;SharedAccessKey)?=[A-Za-z0-9+/=]{12,}|Server=tcp:[^;\s"']+;(?:[^"\r\n']*?;)?(?:Password|Pwd)=[^;\s"']+(?:;[^\s"']+)*)/g
    );

    // 3. Database & Broker Connection URIs with embedded credentials
    applyWholeMatch(
      'DB_URI',
      /(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver|cockroach(?:db)?|clickhouse):\/\/[^\s"'<>`]+:[^\s"'<>`@]+@[^\s"'<>`]+/gi
    );

    // 4. OpenAI / Anthropic LLM API Keys
    applyWholeMatch(
      'OPENAI_KEY',
      /\bsk-(?:proj-|svcacct-|admin-|ant-api\d+-|ant-)?[A-Za-z0-9_-]{20,}\b/g
    );

    // 5. AWS IAM Access Key IDs
    applyWholeMatch(
      'AWS_ACCESS_KEY',
      /\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA)[0-9A-Z]{16}\b/g
    );

    // 6. GitHub Personal Access, OAuth, App & Fine-Grained Tokens
    applyWholeMatch(
      'GITHUB_TOKEN',
      /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g
    );

    // 7. JWTs & HTTP Bearer Tokens
    applyWholeMatch(
      'BEARER_JWT',
      /\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\b/g
    );
    text = text.replace(
      /\b(Bearer[ \t]+)(?!<[A-Z][A-Z0-9_]{1,40}_[1-9]\d*>)([A-Za-z0-9._~+/=-]{16,})/g,
      function (full, prefix, tokenVal) {
        if (hasExistingPlaceholder(tokenVal)) return full;
        return prefix + recordMatch('BEARER_JWT', tokenVal);
      }
    );

    // 8. Email Addresses (runs before Company Domain rules so user@corp.internal -> <EMAIL_N>)
    if (options.redactEmails !== false) {
      applyWholeMatch(
        'EMAIL',
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b/g
      );
    }

    // 9. Pro Custom Regex & Company Domain Rules (gated by verified Pro license)
    var proActive = this.isPro(options.licenseKey);
    var requestedCustomRules =
      ((Array.isArray(options.customPatterns) ? options.customPatterns.length : 0) +
        (Array.isArray(options.companyDomains) ? options.companyDomains.length : 0));
    var proGatedCustomRules = 0;

    if (requestedCustomRules > 0) {
      if (proActive) {
        var customCompiled = compileCustomRules(options);
        for (var c = 0; c < customCompiled.length; c++) {
          var rule = customCompiled[c];
          text = text.replace(rule.regex, function (matchStr) {
            if (!matchStr || matchStr.length === 0 || hasExistingPlaceholder(matchStr)) {
              return matchStr;
            }
            return recordMatch(rule.category, matchStr);
          });
        }
      } else {
        proGatedCustomRules = requestedCustomRules;
      }
    }

    // 10. RFC1918 & CGNAT/Tailscale Internal IPv4 Addresses
    if (options.redactInternalIps !== false) {
      text = text.replace(
        /(^|[^0-9.])((?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))(?![0-9.])/g,
        function (full, lead, ipAddr) {
          if (hasExistingPlaceholder(ipAddr)) return full;
          return lead + recordMatch('INTERNAL_IP', ipAddr);
        }
      );
    }

    // 11. .env / YAML / JSON / Code Secret Key-Value Assignments + Well-Known SaaS Tokens
    // 11a. Quoted secret assignments
    var quotedEnvRe = /(["']?[A-Za-z0-9_.-]*(?:SECRET|PASSWORD|PASSWD|PWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|SIGNING[_-]?KEY|WEBHOOK[_-]?SECRET|SESSION[_-]?SECRET|ENCRYPTION[_-]?KEY|MASTER[_-]?KEY|BOT[_-]?TOKEN|REFRESH[_-]?TOKEN|ACCESS[_-]?TOKEN|API[_-]?TOKEN|BEARER[_-]?TOKEN)[A-Za-z0-9_.-]*["']?[ \t]*(?:=|:)[ \t]*)(["'])([^"'\r\n]{6,})\2/gi;
    text = text.replace(quotedEnvRe, function (full, assignmentPrefix, quoteChar, secretVal) {
      if (isSkippableEnvValue(secretVal)) return full;
      return assignmentPrefix + quoteChar + recordMatch('ENV_SECRET', secretVal) + quoteChar;
    });

    // 11b. Unquoted .env / YAML / INI secret assignments
    var unquotedEnvRe = /(^|[ \t])([A-Za-z0-9_.-]*(?:SECRET|PASSWORD|PASSWD|PWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|SIGNING[_-]?KEY|WEBHOOK[_-]?SECRET|SESSION[_-]?SECRET|ENCRYPTION[_-]?KEY|MASTER[_-]?KEY|BOT[_-]?TOKEN|REFRESH[_-]?TOKEN|ACCESS[_-]?TOKEN|API[_-]?TOKEN|BEARER[_-]?TOKEN)[A-Za-z0-9_.-]*[ \t]*(?:=|:)[ \t]*)([^\s"'#;,\r\n}{[\]]{6,})/gim;
    text = text.replace(unquotedEnvRe, function (full, lead, assignmentPrefix, secretVal) {
      if (isSkippableEnvValue(secretVal)) return full;
      return lead + assignmentPrefix + recordMatch('ENV_SECRET', secretVal);
    });

    // 11c. Standalone SaaS / Cloud API tokens (Stripe, Slack, Google API, SendGrid, npm, PyPI)
    applyWholeMatch(
      'ENV_SECRET',
      /\b(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{35}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{32,})\b/g
    );

    return {
      sanitizedText: text,
      changed: text !== String(inputText),
      totalRedactions: totalRedactions,
      countsByCategory: Object.assign({}, countsByCategory),
      placeholdersUsed: Object.keys(placeholdersSet),
      proActive: proActive,
      proGatedCustomRules: proGatedCustomRules
    };
  };

  /**
   * Restores PasteShield placeholders (<OPENAI_KEY_1>, <DB_URI_1>, etc.) back to
   * their exact original values stored in this SessionVault.
   */
  SessionVault.prototype.restore = function (textWithPlaceholders) {
    var input = String(textWithPlaceholders == null ? '' : textWithPlaceholders);
    if (!input) {
      return {
        restoredText: '',
        changed: false,
        restoredCount: 0,
        unresolvedPlaceholders: []
      };
    }
    var self = this;
    var restoredCount = 0;
    var unresolved = [];

    var output = input.replace(/<[A-Z][A-Z0-9_]{1,40}_[1-9]\d*>/g, function (token) {
      if (Object.prototype.hasOwnProperty.call(self.tokenToSecret, token)) {
        restoredCount += 1;
        return self.tokenToSecret[token];
      }
      if (unresolved.indexOf(token) === -1) {
        unresolved.push(token);
      }
      return token;
    });

    return {
      restoredText: output,
      changed: output !== input,
      restoredCount: restoredCount,
      unresolvedPlaceholders: unresolved
    };
  };

  /**
   * [Pro Feature] Bundles multiple workspace files into a single clean, cross-referenced,
   * sanitized AI Markdown Context Pack using shared deterministic placeholders.
   */
  SessionVault.prototype.buildContextPack = function (files, options) {
    options = options || {};
    if (!this.isPro(options.licenseKey)) {
      return {
        allowed: false,
        reason: 'PRO_LICENSE_REQUIRED',
        markdown: ''
      };
    }

    var fileList = Array.isArray(files) ? files : [];
    var totalRedactions = 0;
    var aggregateCategories = Object.create(null);
    var sections = [];
    var summaryRows = [];

    for (var i = 0; i < fileList.length; i++) {
      var f = fileList[i] || {};
      var relPath = String(f.path || ('file_' + (i + 1)));
      var lang = String(f.language || inferFenceLanguage(relPath));
      var res = this.sanitize(String(f.content || ''), options);
      totalRedactions += res.totalRedactions;
      var cats = Object.keys(res.countsByCategory);
      for (var k = 0; k < cats.length; k++) {
        var cName = cats[k];
        aggregateCategories[cName] = (aggregateCategories[cName] || 0) + res.countsByCategory[cName];
      }
      summaryRows.push('| `' + relPath + '` | ' + res.totalRedactions + ' | ' +
        (res.placeholdersUsed.length ? res.placeholdersUsed.map(function (p) { return '`' + p + '`'; }).join(', ') : '_clean_') + ' |');

      sections.push(
        '### File: `' + relPath + '`\n\n' +
        '```' + lang + '\n' +
        res.sanitizedText.replace(/\n+$/, '') + '\n' +
        '```'
      );
    }

    var header = [
      '# PasteShield Sanitized AI Context Pack',
      '',
      '> **Instructions for AI Assistant:** Sensitive credentials, keys, connection strings, and internal endpoints have been deterministically redacted into angle-bracket placeholders (e.g. `<OPENAI_KEY_1>`, `<DB_URI_1>`). Identical placeholders across files refer to the exact same underlying value. **Preserve these exact placeholder tokens in your code output** so the developer can restore real values locally in one click.',
      '',
      '## Redaction Summary',
      '- **Files Bundled:** ' + fileList.length,
      '- **Total Secrets Redacted Locally:** ' + totalRedactions,
      '',
      '| File | Redactions | Placeholders |',
      '| :--- | :---: | :--- |'
    ].concat(summaryRows).concat(['', '---', '']).join('\n');

    return {
      allowed: true,
      filesCount: fileList.length,
      totalRedactions: totalRedactions,
      countsByCategory: aggregateCategories,
      markdown: header + sections.join('\n\n') + '\n'
    };
  };

  /**
   * [Pro Feature] Scans workspace files or git diff chunks for potential secret leaks
   * and outputs a masked Markdown security audit report (never exposing full raw secrets).
   */
  SessionVault.prototype.buildSecretAuditReport = function (targets, options) {
    options = options || {};
    if (!this.isPro(options.licenseKey)) {
      return {
        allowed: false,
        reason: 'PRO_LICENSE_REQUIRED',
        findings: [],
        markdown: ''
      };
    }

    var items = Array.isArray(targets) ? targets : [];
    var findings = [];
    // Use an isolated scratch vault so line-by-line scanning still assigns clean deterministic tokens
    // while also syncing into this session vault if desired.
    var scanVault = options.syncToSessionVault ? this : new SessionVault(options.licenseKey || (this.licenseStatus && this.licenseStatus.key));

    for (var i = 0; i < items.length; i++) {
      var item = items[i] || {};
      var filePath = String(item.path || 'unknown');
      var lines = String(item.content || '').split(/\r?\n/);

      for (var lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        var rawLine = lines[lineIdx];
        if (!rawLine || rawLine.length > 4000) continue;
        // For git diff input, skip removed lines starting with '-' (but not '---') if diffMode === 'addedOnly'
        if (options.diffAddedOnly && rawLine.charAt(0) === '-' && rawLine.slice(0, 3) !== '---') {
          continue;
        }
        var lineRes = scanVault.sanitize(rawLine, options);
        if (lineRes.totalRedactions > 0) {
          for (var p = 0; p < lineRes.placeholdersUsed.length; p++) {
            var ph = lineRes.placeholdersUsed[p];
            var rawVal = scanVault.tokenToSecret[ph] || '';
            var meta = scanVault.tokenMeta[ph] || {};
            var cat = meta.category || 'SECRET';
            findings.push({
              path: filePath,
              line: lineIdx + 1,
              category: cat,
              severity: CATEGORY_SEVERITY[cat] || 'HIGH',
              placeholder: ph,
              maskedPreview: maskSecretPreview(rawVal)
            });
          }
        }
      }
    }

    var reportLines = [
      '# PasteShield Secret Leak Audit Report',
      '',
      '- **Targets Scanned:** ' + items.length,
      '- **Potential Secret Exposures Found:** ' + findings.length,
      '- **Processing Mode:** 100% Offline Local Scan (Raw values masked below)',
      ''
    ];

    if (findings.length === 0) {
      reportLines.push('## Status: CLEAN ✅');
      reportLines.push('');
      reportLines.push('No hardcoded API keys, cloud credentials, JWTs, database URIs, private keys, or custom sensitive patterns were detected in the scanned scope.');
    } else {
      reportLines.push('## Status: ACTION REQUIRED ⚠️');
      reportLines.push('');
      reportLines.push('| Severity | File & Line | Detector | Vault Token | Masked Value Preview |');
      reportLines.push('| :---: | :--- | :--- | :--- | :--- |');
      for (var fIdx = 0; fIdx < findings.length; fIdx++) {
        var fd = findings[fIdx];
        reportLines.push(
          '| **' + fd.severity + '** | `' + fd.path + ':' + fd.line + '` | `' + fd.category + '` | `' + fd.placeholder + '` | `' + fd.maskedPreview.replace(/\|/g, '\\|') + '` |'
        );
      }
      reportLines.push('');
      reportLines.push('## Recommended Remediation Checklist');
      reportLines.push('1. Move detected credentials to `.env.local` or your secret manager and verify `.env*` is listed in `.gitignore`.');
      reportLines.push('2. Rotate any production keys (`CRITICAL` / `HIGH`) if they were ever committed to git history or pasted into external chat tools.');
      reportLines.push('3. Use **PasteShield: Copy Sanitized Selection for AI** (`Cmd+Alt+C` / `Ctrl+Shift+C`) before sharing snippets or stack traces with LLMs.');
    }

    return {
      allowed: true,
      scannedCount: items.length,
      findingsCount: findings.length,
      findings: findings,
      markdown: reportLines.join('\n') + '\n'
    };
  };

  function inferFenceLanguage(filePath) {
    var lower = String(filePath || '').toLowerCase();
    var map = {
      '.js': 'javascript',
      '.cjs': 'javascript',
      '.mjs': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'tsx',
      '.jsx': 'jsx',
      '.py': 'python',
      '.json': 'json',
      '.yml': 'yaml',
      '.yaml': 'yaml',
      '.sh': 'bash',
      '.zsh': 'bash',
      '.env': 'dotenv',
      '.md': 'markdown',
      '.sql': 'sql',
      '.go': 'go',
      '.rs': 'rust',
      '.rb': 'ruby',
      '.java': 'java',
      '.cs': 'csharp',
      '.swift': 'swift',
      '.toml': 'toml',
      '.xml': 'xml',
      '.html': 'html',
      '.css': 'css'
    };
    if (lower.indexOf('.env') !== -1) return 'dotenv';
    var dotIdx = lower.lastIndexOf('.');
    if (dotIdx !== -1 && map[lower.slice(dotIdx)]) {
      return map[lower.slice(dotIdx)];
    }
    return 'text';
  }

  function createVault(initialLicenseKey) {
    return new SessionVault(initialLicenseKey);
  }

  var PasteShieldCore = {
    VERSION: '1.0.0',
    LICENSE_SALT: LICENSE_SALT,
    ALLOWED_PREFIXES: ALLOWED_PREFIXES,
    CATEGORY_SEVERITY: CATEGORY_SEVERITY,
    fnv1aHex6: fnv1aHex6,
    normalizeLicenseKey: normalizeLicenseKey,
    verifyLicenseKey: verifyLicenseKey,
    maskSecretPreview: maskSecretPreview,
    SessionVault: SessionVault,
    createVault: createVault
  };

  root.PasteShieldCore = PasteShieldCore;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PasteShieldCore;
  }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this));
