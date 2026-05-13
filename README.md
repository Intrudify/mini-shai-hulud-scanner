# Mini Shai-Hulud Scanner

A free, offline scanner for the npm/PyPI supply chain worm that's currently chewing through major packages. Built by the [Intrudify](https://intrudify.com) team. No signup, no telemetry, runs entirely offline.

NHS CC-4781 · CVE-2026-45321 (CVSS 9.6) · GHSA-g7cv-rxg3-hmpx

---
## What this is
If you've run `npm install` or `pip install` in the past few weeks, this is for you.

Especially if you've touched `@tanstack/*`, `@uipath/*`, `@mistralai/*`, `@cap-js/*`, or PyPI's `litellm`, `mistralai`, `guardrails-ai`, `lightning`, or `telnyx`. Those are the confirmed-poisoned namespaces. 149 packages total, 400+ malicious versions tracked so far.

**Mini Shai-Hulud** is the worm doing the damage. It steals your npm and GitHub credentials, plants persistence across macOS, Linux, and Windows, and (the part most people miss) leaves behind a booby-trapped token. Revoke it from the infected machine and it triggers `rm -rf ~/`. Your home directory, gone. Cleanup order matters.

This scanner checks all 19 known indicators of compromise across packages, lockfiles, persistence mechanisms, payload hashes, C2 traffic, git history, and CI environments. It only reads. It never writes, deletes, or phones home.

Three scripts, one job: Python, Bash, PowerShell. Pick the one that fits your stack.

---
 
## Why we built this

[Intrudify](https://intrudify.com) is Europe's first fully autonomous AI pentester for web applications. The pitch is simple: same output as a $30K human pentest team, delivered in hours instead of weeks, with an audit-ready report and step-by-step remediation guidance for NIS2, SOC2, and ISO27001. If you ship code and don't have a security team, that's the gap we close.

This scanner is one piece of that. It's free because supply chain worms move faster than procurement cycles. A developer staring at a CVE feed at 11pm doesn't need a sales call. They need a tool that runs in 30 seconds and tells them whether they're cooked.

For active compromises (CI/CD pipeline hijacks, GitHub Actions OIDC token abuse, npm/PyPI supply chain IR), reach out directly: **marc@intrudify.com**

---

If you've installed an npm or PyPI package in the last few weeks, especially anything from `@tanstack/*`, `@uipath/*`, `@mistralai/*`, `@cap-js/*`, or PyPI's `litellm`, `mistralai`, `guardrails-ai`, `lightning`, or `telnyx`, your machine may be compromised.

The **Mini Shai-Hulud** worm steals credentials, plants persistence across macOS, Linux, and Windows, and can wipe your home directory if you handle cleanup in the wrong order.

This scanner checks for all 19 known indicators. It only reads. It never writes, deletes, or sends anything off your machine.

---

## Before you run: read this first

The worm plants a booby-trapped npm token. Revoking it from the infected machine triggers `rm -rf ~/`. Order matters.

**If the scanner finds CRITICAL findings, do this in order:**

1. **Disconnect** the machine from the network (pull the cable or turn off Wi-Fi)
2. **Take a snapshot or disk image** before touching anything
3. **From a different machine**, log into npmjs.com and GitHub and revoke tokens there
4. Then clean up the infected machine

---

## How to run: 3 steps

### Step 1: pick your script

| You're on... | Use this |
|---|---|
| macOS or Linux | `scan_cc4781.sh` (or `scan_cc4781.py` if you prefer Python) |
| Windows | `scan_cc4781.ps1` (or `scan_cc4781.py` with native Python) |
| CI / Docker | `scan_cc4781.py` or `scan_cc4781.sh` |

### Step 2: run it from your project folder

```bash
# macOS / Linux
chmod +x scan_cc4781.sh
./scan_cc4781.sh --deep
```

```powershell
# Windows PowerShell
.\scan_cc4781.ps1 -Deep
```

```bash
# Python (any OS)
python3 scan_cc4781.py --deep
```

The `--deep` / `-Deep` flag recurses into all `node_modules` under the current directory. Recommended if you have a monorepo or multiple projects.

If PowerShell blocks the script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scan_cc4781.ps1 -Deep
```

### Step 3: read the result

```
RESULT: 0 CRITICAL / 0 HIGH   →  you're clean
RESULT: X CRITICAL / Y HIGH   →  stop and follow the steps above before doing anything else
```

`CRITICAL` = confirmed compromise indicator. Act immediately.
`HIGH` = suspicious. Investigate. Some HIGH findings are expected false positives (see below).

---

## Expected output on a clean machine

```
CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner
Host: your-hostname  OS: your-os
Checking 149 npm packages (400+ malicious versions), 5 PyPI packages

[OK]   gh-token-monitor process not detected
[HIGH] payload-artefact: sysmon.py  ->  .../coverage/sysmon.py    <- false positive: Python coverage package
[HIGH] payload-artefact: execution.js  ->  .../n8n/.../execution.js  <- false positive: n8n
[OK]   git-tanstack.com does not resolve
[OK]   No malicious optionalDependencies github: references found
[OK]   No attacker exfil commits in git log

RESULT: 0 CRITICAL / 4 HIGH
```

The `sysmon.py` and `execution.js` HIGH findings are **false positives**: the filenames match the worm's payload names but the SHA-256 hashes do not. CRITICAL only fires when the hash matches a confirmed-malicious payload.

---

## All flags

| Flag | Bash / Python | PowerShell | What it does |
|---|---|---|---|
| Deep scan | `--deep` | `-Deep` | Recurse all `node_modules` under CWD |
| Target dir | `--npm-dir /path` | `-NpmDir C:\path` | Scan a specific `node_modules` folder |
| JSON output | `--json` | `-Json` | Machine-readable output for SIEM / SOAR |

JSON output format: `{ "host": "...", "findings": [{ "severity": "CRITICAL|HIGH", "category": "...", "detail": "...", "path": "..." }] }`

---

## What the scanner checks (19 indicators)

| # | Category | What it looks for |
|---|---|---|
| 1 | npm versions | 149 packages, 400+ confirmed-malicious exact versions |
| 2 | Lockfiles | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| 3 | PyPI | `litellm`, `telnyx`, `lightning`, `mistralai`, `guardrails-ai` |
| 4 | Persistence | macOS LaunchAgent, Linux systemd, Windows Scheduled Task + HKCU Run key |
| 5 | Persistence | Claude Code `SessionStart` hook, VS Code `folderOpen` task |
| 6 | Payload files | 13 filenames + SHA-256 against 11 known-bad hashes |
| 7 | C2 hosts | 11 domains in `/etc/hosts`, proxy env vars, WinHTTP |
| 8 | C2 DNS | Resolves all 11 C2 domains |
| 9 | C2 connections | Active TCP to 5 tracked C2 IPs |
| 10 | `package.json` | `optionalDependencies github:tanstack/router` injection |
| 11 | `package.json` | `prepare: bun run tanstack_runner.js` injection |
| 12 | Workflows | `.github/workflows/codeql_analysis.yml`, `format-check.yml` |
| 13 | Git log | Attacker exfil commits (`claude@users.noreply.github.com`) |
| 14 | Git branches | Dune-themed worm branches, `dependabout/` typosquat |
| 15 | npm tokens | RANSOM TOKEN detection |
| 16 | Shell history | C2 domains, IPs, payload filenames |
| 17 | CI environment | GitHub Actions credential leakage |
| 18 | Git remotes | Attacker accounts and C2 domains |
| 19 | Advanced persistence | `sysmon`/`pgmon` service disguise, `litellm_init.pth`, Kubernetes DaemonSet, WAV steganography |

---

## Attack waves covered

| Wave | Date | Packages | Publisher |
|---|---|---|---|
| TanStack | May 2026 | 43 `@tanstack/*` packages | `voicproducoes` |
| UiPath / JFrog | May 2026 | 66 `@uipath/*` packages | `voicproducoes` / `zblgg` |
| SAP @cap-js | April 2026 | `@cap-js/db-service`, `@cap-js/sqlite`, `@cap-js/postgres`, `mbt` | `cloudmtabot` |
| PyPI | Feb--April 2026 | `litellm`, `telnyx`, `lightning`, `mistralai`, `guardrails-ai` | various |

**Important:** `npm audit signatures` passing does **not** mean you are safe. Mini Shai-Hulud is the first documented attack generating valid SLSA Build Level 3 provenance via a GitHub Actions OIDC pipeline hijack. Signatures verify build provenance, not that the build pipeline itself was clean.

---

## Technical background

The worm uses three-layer obfuscation: obfuscator.io, then a Fisher-Yates substitution cipher (PBKDF2-SHA256, 200,000 iterations), then AES-256-GCM. It exfiltrates credentials via the Session Protocol CDN, GitHub GraphQL dead-drops, an ICP blockchain canister, and WAV steganography.

Persistence is planted as a macOS LaunchAgent, Linux systemd unit, Windows Scheduled Task or HKCU Run key, Claude Code `SessionStart` hook, VS Code `folderOpen` task, and a Python `.pth` startup file. On compromised CI runners it plants a Kubernetes DaemonSet.

The RANSOM TOKEN (`IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`) is paired with a `gh-token-monitor` daemon that polls `api.github.com/user` every 60 seconds. A 40x response triggers `rm -rf ~/` on Linux/macOS or the Windows equivalent.

---

## IOC sources

Aggregated from GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity, Socket.dev, Wiz Threat Research, Snyk, Aikido Security, Orca Security, Mend.io (as of 2026-05-13).

Detection rules: Sigma `5299fadf-f228-4526-8274-251db1960be9` (Shai-Hulud Malicious Bun Execution), Palo Alto ATP signature `87120`.

---

## References

- [NHS CC-4781](https://digital.nhs.uk/cyber-alerts/2026/cc-4781)
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [CVE-2026-45321](https://nvd.nist.gov/vuln/detail/CVE-2026-45321)
- [StepSecurity: Mini Shai-Hulud is back](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [JFrog: Shai-Hulud here we go again](https://research.jfrog.com/post/shai-hulud-here-we-go-again/)
- [Wiz: Mini Shai-Hulud strikes again](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)

---

## Need help with an active compromise?

Intrudify specialises in npm/PyPI supply chain IR, CI/CD pipeline hijacks, and GitHub Actions OIDC token abuse.

**Contact: [marc@intrudify.com](mailto:marc@intrudify.com) &nbsp;·&nbsp; [intrudify.com](https://intrudify.com)**
