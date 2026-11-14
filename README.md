<div align="center">

<img src="./assets/icon.png" alt="PasteShield Logo" width="88" />

# PasteShield — Reversible AI Prompt & Clipboard Secret Sanitizer

**Redact API keys, `.env` secrets, JWTs, database URIs, cloud connection strings & internal IPs before prompting ChatGPT, Claude, Cursor, or Copilot — and restore real credentials in 1 click.**

[![Download VS Code & Cursor .VSIX](https://img.shields.io/badge/Download_.VSIX_(v1.0.0)-VS_Code_%26_Cursor-10b981?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://github.com/963239327/pasteshield-secret-sanitizer/releases/download/v1.0.0/pasteshield-ai-secret-sanitizer-1.0.0.vsix)
[![Live Browser Playground](https://img.shields.io/badge/Try_Live_Playground-100%25_In_Browser-06b6d4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://963239327.github.io/craftleaf-studio/extensions/pasteshield/)
[![Unlock PasteShield Pro](https://img.shields.io/badge/PasteShield_Pro-%249_Lifetime_Offline_Key-f59e0b?style=for-the-badge)](https://963239327.github.io/craftleaf-studio/extensions/pasteshield/#pro)

![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)
![100% Offline](https://img.shields.io/badge/network_calls-0_(100%25_local_RAM)-blue)
![Node & Bun Ready](https://img.shields.io/badge/CLI-Node.js_%26_Bun-339933)
![License MIT](https://img.shields.io/badge/license-MIT-brightgreen)

[**Live Playground →**](https://963239327.github.io/craftleaf-studio/extensions/pasteshield/) · [**1-Click `.vsix` Installer →**](https://github.com/963239327/pasteshield-secret-sanitizer/releases/download/v1.0.0/pasteshield-ai-secret-sanitizer-1.0.0.vsix) · [**CLI & JS Library ↓**](#quickstart-cli--nodejs--bun) · [**PasteShield Pro ($9) ↓**](#free-vs-pasteshield-pro-comparison)

</div>

---

## Why Developers Use PasteShield Instead of `***REDACTED***`

Every day, developers paste `.env` configs, Kubernetes manifests, crash logs, and `curl` traces into ChatGPT, Claude, DeepSeek, or Cursor. Manually replacing values with `***REDACTED***` breaks two things:
1. **LLMs lose cross-variable identity** (the model cannot tell if two `***` strings are the same database host or two different tokens).
2. **Pasting the AI's refactored code back breaks your app** until you manually hunt down and re-insert every secret.

**PasteShield solves both in `<1ms` with zero cloud calls:**
- Maps each unique secret to a **deterministic semantic token** (`<OPENAI_KEY_1>`, `<DB_URI_1>`, `<GITHUB_TOKEN_1>`, `<INTERNAL_IP_1>`).
- Identical secrets across multiple lines or files always map to the **exact same placeholder** so the LLM preserves variable relationships.
- **Restores your exact original secrets in 1 click** (`Cmd+Alt+R` in VS Code / Cursor, or `pasteshield restore` in CLI) when you paste the AI's solution back.

<p align="center">
  <img src="./assets/screenshot_1_before_after.png" alt="PasteShield Before and After Reversible AI Secret Sanitization in VS Code and Cursor" width="900" />
</p>

---

## Before & After Roundtrip Example

### 1. Raw Local Snippet (Stays on Your Machine)
```dotenv
# Production Checkout Service (.env)
OPENAI_API_KEY=sk-proj-EXAMPLE000000000000000000000001
GITHUB_DEPLOY_TOKEN=ghp_EXAMPLE00000000000000000000000001
DATABASE_URL="postgresql://svc_orders:Pr0dP4ss!@10.24.8.15:5432/orders_db"
ONCALL_EMAIL=secops@acme-fintech.example
```

### 2. Sanitized Prompt Sent to ChatGPT / Claude / Cursor (`Cmd+Alt+C`)
```dotenv
# Production Checkout Service (.env)
OPENAI_API_KEY=<OPENAI_KEY_1>
GITHUB_DEPLOY_TOKEN=<GITHUB_TOKEN_1>
DATABASE_URL="<DB_URI_1>"
ONCALL_EMAIL=<EMAIL_1>
```

### 3. AI Generates Refactored Code -> 1-Click Local Restore (`Cmd+Alt+R`)
```ts
// AI outputs placeholders -> PasteShield restores real credentials locally in <1ms:
export const checkoutEnv = {
  openAiKey: "sk-proj-EXAMPLE000000000000000000000001",
  databaseUrl: "postgresql://svc_orders:Pr0dP4ss!@10.24.8.15:5432/orders_db",
  deployToken: "ghp_EXAMPLE00000000000000000000000001",
  alertEmail: "secops@acme-fintech.example",
};
```

---

## 3 Ways to Use PasteShield

### Option A: VS Code, Cursor & VSCodium Extension (`.vsix`)
1. Download **[`pasteshield-ai-secret-sanitizer-1.0.0.vsix`](https://github.com/963239327/pasteshield-secret-sanitizer/releases/download/v1.0.0/pasteshield-ai-secret-sanitizer-1.0.0.vsix)** from [GitHub Releases](https://github.com/963239327/pasteshield-secret-sanitizer/releases/latest).
2. In VS Code or Cursor, open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) -> **`Extensions: Install from VSIX...`** -> select the `.vsix` file (or run `code --install-extension pasteshield-ai-secret-sanitizer-1.0.0.vsix`).
3. Highlight any code/log and press:
   - **`Cmd+Alt+C`** (`Ctrl+Alt+C`) — **Copy Sanitized Selection for AI**
   - **`Cmd+Alt+R`** (`Ctrl+Alt+R`) — **Restore Original Values from Clipboard / Selection**
   - **`Cmd+Alt+S`** (`Ctrl+Alt+S`) — **Sanitize Current Editor In-Place**

### Option B: Instant Zero-Install Browser Playground
Need to scrub a crash log or `.env` snippet right now without installing anything?
👉 **[Open Live PasteShield Browser Playground](https://963239327.github.io/craftleaf-studio/extensions/pasteshield/)** *(100% client-side JS, works offline after page load)*.

### Option C: Quickstart CLI & JavaScript SDK (Node.js / Bun, 0 Dependencies)

```bash
git clone https://github.com/963239327/pasteshield-secret-sanitizer.git
cd pasteshield-secret-sanitizer

# Run interactive roundtrip demo in your terminal:
node bin/pasteshield-cli.js demo

# Sanitize clipboard on macOS before pasting into ChatGPT / Claude:
pbpaste | node bin/pasteshield-cli.js sanitize --vault .pasteshield-vault.json | pbcopy

# Restore real values into the AI's code reply on your clipboard:
pbpaste | node bin/pasteshield-cli.js restore --vault .pasteshield-vault.json | pbcopy

# Scan workspace or uncommitted `git diff` for accidental secret leaks:
node bin/pasteshield-cli.js scan --git-diff
```

Use `sanitizer-core.js` directly as a zero-dependency CommonJS or browser module:
```js
const PasteShieldCore = require('./sanitizer-core');

const vault = PasteShieldCore.createVault();
const { sanitizedText, totalRedactions } = vault.sanitize(process.env.RAW_LOG_SNIPPET || 'OPENAI_API_KEY=sk-proj-1234567890abcdefghijklm');
console.log(sanitizedText); // OPENAI_API_KEY=<OPENAI_KEY_1>

const { restoredText } = vault.restore(`export const key = "${sanitizedText.split('=')[1]}";`);
```

---

## 10 Built-In Secret & PII Detectors (Free Forever)

| Semantic Token | Detected Credentials & Formats |
| :--- | :--- |
| `<OPENAI_KEY_N>` | OpenAI (`sk-...`, `sk-proj-...`, `sk-svcacct-...`) & Anthropic (`sk-ant-...`) LLM keys |
| `<AWS_ACCESS_KEY_N>` | AWS IAM Access Key IDs (`AKIA...`, `ASIA...`, `ABIA...`, `ACCA...`) |
| `<GITHUB_TOKEN_N>` | GitHub Classic PATs (`ghp_`), OAuth/App (`gho_`, `ghu_`, `ghs_`, `ghr_`), Fine-Grained (`github_pat_`) |
| `<BEARER_JWT_N>` | 3-part signed JWTs (`eyJ...`) & HTTP `Authorization: Bearer <token>` headers |
| `<AZURE_CONN_STR_N>` | Azure Storage, Service Bus, Cosmos DB, IoT Hub & Azure SQL connection strings |
| `<DB_URI_N>` | PostgreSQL, MySQL, MariaDB, MongoDB, Redis, AMQP & ClickHouse URIs with embedded credentials |
| `<PRIVATE_KEY_BLOCK_N>` | Multi-line PEM, RSA, EC, OpenSSH & PGP `BEGIN ... PRIVATE KEY` blocks |
| `<INTERNAL_IP_N>` | RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`) & Tailscale/CGNAT (`100.64-127.x`) private IPv4s |
| `<EMAIL_N>` | Internal & customer email addresses |
| `<ENV_SECRET_N>` | `.env` / YAML / JSON assignments (`*_SECRET`, `*_PASSWORD`, `*_TOKEN`, `*_API_KEY`) + Stripe, Slack, Google API, SendGrid, npm & PyPI tokens |

---

## Free vs. PasteShield Pro Comparison

<p align="center">
  <img src="./assets/screenshot_2_context_pack.png" alt="PasteShield Pro Multi-File Sanitized AI Markdown Context Pack and Git Diff Audit" width="900" />
</p>

| Feature | Free Community (`$0`) | PasteShield Pro (`$9` One-Time) | Studio All-Access (`$19` One-Time) |
| :--- | :---: | :---: | :---: |
| **10 Built-In Cloud, LLM, DB, JWT & PEM Detectors** | ✅ | ✅ | ✅ |
| **1-Click Reversible Session Vault (`Cmd+Alt+C` / `Cmd+Alt+R`)** | ✅ | ✅ | ✅ |
| **Zero-Dependency Node/Bun CLI & Browser Playground** | ✅ | ✅ | ✅ |
| **100% Offline Air-Gapped Execution (Zero Telemetry)** | ✅ | ✅ | ✅ |
| **Custom Corporate Domain Redaction (`*.corp.acme.internal` -> `<COMPANY_DOMAIN_1>`)** | — | ✅ | ✅ |
| **Custom Regex Rules (Jira/Linear IDs, Customer Keys, Proprietary Tokens)** | — | ✅ | ✅ |
| **Multi-File Sanitized AI Markdown Context Pack Exporter** | — | ✅ | ✅ |
| **Workspace & `git diff` Markdown Security Audit Report** | — | ✅ | ✅ |
| **Also Unlocks 4 Sister CraftLeaf Pro Tools** *(CleanPrint, IDPhoto 4×6, Invoice CRM, CardSheet Duplex)* | — | — | ✅ (`STUDIOALL-...` Key) |

👉 **[Get PasteShield Pro ($9 Lifetime Offline Key)](https://963239327.github.io/craftleaf-studio/extensions/pasteshield/#pro)** · **[Get Studio All-Access Pass ($19 — Unlocks All 5 Tools)](https://963239327.github.io/craftleaf-studio/#all-access)**

---

## More Privacy-First Tools by CraftLeaf Studio

All CraftLeaf tools run **100% client-side in your browser or local IDE** with zero file uploads:
- 🖨️ **[CleanPrint & AI-Chat to PDF Extension](https://963239327.github.io/craftleaf-studio/extensions/cleanprint/)** — Strip clutter & dark backgrounds from ChatGPT/Claude/Docs and export eco low-ink vector PDFs.
- 🪪 **[Passport & Visa 4×6" ID Photo Sheet Maker](https://963239327.github.io/craftleaf-studio/tools/id-photo/)** — Biometric US/Schengen/UK/Canada/China visa photo cropper tiled onto a `$0.39` 4×6" print sheet.
- 🧾 **[No-Signup Freelancer Invoice PDF Studio](https://963239327.github.io/craftleaf-studio/tools/invoice/)** — Instant multi-currency client invoices with local CRM memory & payment QR codes.
- 🗂️ **[CardSheet Duplex Flashcard & PnP Print Studio](https://963239327.github.io/craftleaf-studio/cardsheet/)** — Millimeter-accurate front/back duplex offset calibration for flashcards and tabletop cards.
- 🎲 **[Play *Star Chef Showdown* Free in Browser](https://963239327.github.io/craftleaf-studio/play/)** — Original 2-player rondel + blackjack-heat Print-and-Play board game with solo AI opponent.

## License

MIT © [CraftLeaf & Pixel Studio](https://963239327.github.io/craftleaf-studio/)
