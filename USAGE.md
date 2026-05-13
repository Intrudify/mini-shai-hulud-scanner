# Usage Guide — Mini Shai-Hulud Scanner

Scanner for NHS CC-4781 / CVE-2026-45321 (Mini Shai-Hulud npm/PyPI supply chain worm).  
Three scripts, same checks, pick what fits your environment.

---

## Before you run

**RANSOM TOKEN:** If this system is already compromised, it may have an npm token named  
`IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`.  
A daemon polls GitHub every 60 s and wipes the machine if that token is revoked.

**Do not revoke any npm tokens until the machine is network-isolated.**

Remediation order: **isolate network -> forensic image -> revoke token from a separate machine.**

---

## Python

**Requires:** Python 3.9+, stdlib only.

```sh
python3 scan_cc4781.py
python3 scan_cc4781.py --deep                          # recurse all node_modules under CWD
python3 scan_cc4781.py --npm-dir /path/node_modules   # target a specific node_modules
python3 scan_cc4781.py --json                          # JSON output for SIEM/SOAR
```

Works on Linux, macOS, Windows.

**Verified output — tested against Intrudify-Web (Next.js, live node_modules) and Intrudify2 (Python):**
```
CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner
Host: DESKTOP-GICNBJB  OS: Windows 11
Checking 149 npm packages (400+ malicious versions), 5 PyPI packages

[INFO] Checking 149 npm packages for compromised versions ...
[INFO] Scanning lockfiles for compromised package entries ...
[OK]   No attacker exfil commits in git log
[OK]   No Dune-themed worm branches found
[OK]   No malicious optionalDependencies github: references found
[OK]   No malicious prepare script patterns found
[OK]   gh-token-monitor process not detected
[HIGH] payload-artefact: sysmon.py (sha256=01f8..., size=19,734 bytes)
  -> ...\site-packages\coverage\sysmon.py    <- false positive: Python coverage
[HIGH] payload-artefact: execution.js (sha256=1e84..., size=114 bytes)
  -> ...\@n8n\api-types\dist\push\execution.js  <- false positive: n8n
[HIGH] c2-dns-resolves: seed1.getsession.org -> 157.90.192.70
[HIGH] c2-dns-resolves: seed2.getsession.org -> 37.27.236.229
[HIGH] c2-dns-resolves: seed3.getsession.org -> 185.150.191.51
[HIGH] c2-dns-resolves: api.masscan.cloud -> 188.114.96.8
[HIGH] c2-dns-resolves: filev2.getsession.org -> 157.90.192.70
[OK]   git-tanstack.com does not resolve
[HIGH] slsa-provenance-warning (standing advisory)
RESULT: 0 CRITICAL / 9 HIGH
```

**Interpreting the findings:**

| Finding | Severity | What it means |
|---|---|---|
| `payload-artefact` (HIGH, not CRITICAL) | Filename hit, hash miss | Check the path. `coverage\sysmon.py` and `@n8n\...\execution.js` are false positives. CRITICAL only fires when hash matches a known-bad payload. |
| `c2-dns-resolves` for `seed*.getsession.org` | HIGH | Session Protocol seed nodes are globally routable — this resolves from any internet-connected machine. Not a compromise indicator on its own. |
| `slsa-provenance-warning` | HIGH | Standing advisory on all machines — not a machine-specific finding. |
| 0 CRITICAL | | **Intrudify repos are clean.** No compromised npm packages, no persistence implants, no attacker commits. |

---

## Bash

**Requires:** Bash 4+. Optional: `python3` (JSON parsing), `dig` or `nslookup`, `ss`, `kubectl`.

```sh
chmod +x scan_cc4781.sh
./scan_cc4781.sh
./scan_cc4781.sh --deep
./scan_cc4781.sh --npm-dir /path/node_modules
./scan_cc4781.sh --json
```

Works on Linux and macOS. Runs under Git Bash on Windows.

Same checks and output format as the Python version. Expect the same false positives (see Python section above).

**Verified output — tested against Intrudify-Web (Next.js, live node_modules):**
```
CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner (Shell)
Host: DESKTOP-GICNBJB  OS: MINGW64_NT-10.0-26200
Checking 149 npm packages, 5 PyPI packages

[OK]   gh-token-monitor process not running
[HIGH] payload-artefact: execution.js (sha256=1e84..., size=114 bytes)
  -> /c/Users/.../n8n/.../execution.js       <- false positive: n8n
[HIGH] payload-artefact: sysmon.py (sha256=01f8..., size=19734 bytes)
  -> /c/Users/.../coverage/sysmon.py         <- false positive: Python coverage
[OK]   git-tanstack.com does not resolve
[OK]   seed1.getsession.org does not resolve
... (all 11 C2 domains)
[OK]   No malicious optionalDependencies github: references found
[OK]   No malicious prepare script patterns found
[OK]   No attacker exfil commits found in git log
[OK]   No Dune-themed worm propagation branches found
[OK]   npm token list failed (not authenticated?)
[HIGH] slsa-provenance-warning (standing advisory -- see below)
RESULT: 0 CRITICAL / 4 HIGH
```

**DNS note for Git Bash on Windows:** `dig` queries the local DNS resolver. If your router intercepts NXDOMAIN responses (returning its own IP), the scanner filters RFC1918 addresses and correctly shows C2 domains as "does not resolve". Use the Python scanner for a more reliable DNS check.

> **Note:** On Windows with Git Bash, the payload file scan searches `$HOME` recursively. On machines with large `node_modules` trees (e.g. n8n), this can take 5-10 minutes due to Git Bash file system overhead. On Linux/macOS this takes 1-2 minutes.

---

## PowerShell

**Requires:** PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform).

```powershell
.\scan_cc4781.ps1
.\scan_cc4781.ps1 -Deep
.\scan_cc4781.ps1 -NpmDir C:\projects\app\node_modules
.\scan_cc4781.ps1 -Json
```

Extra Windows checks: Scheduled Task, HKCU Run key, Startup folder.

**Note — Windows Defender:** The script contains IOC strings (including the ransom token description) that Windows Defender flags as malicious content. This is expected. To run it, add a folder exclusion in Defender for the script directory, or run it on an isolated forensic workstation where AV exceptions can be applied safely.

```powershell
# Add exclusion (run as Administrator):
Add-MpPreference -ExclusionPath "C:\path\to\scanner\folder"

# Then run:
.\scan_cc4781.ps1
```

---

## Output format

| Prefix | Meaning |
|---|---|
| `[CRITICAL]` | Confirmed compromise indicator — act immediately |
| `[HIGH]` | Suspicious — investigate |
| `[OK]` | Check passed |
| `[INFO]` | Progress message |

**JSON mode** (`--json` / `-Json`): outputs a single object `{ "host": "...", "findings": [...] }`.  
Each finding: `{ "severity": "CRITICAL|HIGH", "category": "...", "detail": "...", "path": "..." }`.

---

## What each check covers

| # | Category | What it looks for |
|---|---|---|
| 1 | npm versions | 149+ packages, exact compromised versions |
| 2 | Lockfiles | package-lock.json / pnpm-lock.yaml / yarn.lock |
| 3 | PyPI | litellm, telnyx, lightning, mistralai, guardrails-ai |
| 4 | Persistence | LaunchAgent / systemd / Scheduled Task / Run key |
| 5 | Persistence | Claude Code hook, VS Code folderOpen task |
| 6 | Payload files | 13 filenames + SHA-256 against 11 known-bad hashes |
| 7 | C2 domains | 11 domains in /etc/hosts, proxy env, WinHTTP |
| 8 | C2 DNS | Resolves all 11 C2 domains |
| 9 | C2 connections | Active TCP to 5 C2 IPs |
| 10 | package.json | `optionalDependencies github:tanstack/router` injection |
| 11 | package.json | `prepare: bun run tanstack_runner.js` injection |
| 12 | Workflows | `.github/workflows/codeql_analysis.yml`, `format-check.yml` |
| 13 | Git log | Attacker exfil commits (`claude@users.noreply.github.com`) |
| 14 | Git branches | Dune-themed worm branches, `dependabout/` typosquat |
| 15 | npm tokens | RANSOM TOKEN detection |
| 16 | Shell history | C2 domains, IPs, payload filenames in history |
| 17 | CI env | GitHub Actions credential variables |
| 18 | Git remotes | Attacker accounts, C2 domains in remotes |
| 19 | Adv. persistence | sysmon/pgmon disguise, litellm_init.pth, Kubernetes DaemonSet |

---

## If you get CRITICAL findings

1. **Stop.** Do not revoke any npm tokens yet.
2. Pull the network cable or disable the NIC.
3. Take a forensic image of the drive.
4. From a **separate, clean machine**, revoke the npm token on npmjs.com.
5. Check all secrets that ran through CI during the compromise window (GitHub tokens, AWS keys, npm tokens).
6. Review git log for `claude@users.noreply.github.com` commits — these are attacker dead-drop exfiltration runs.
7. Update all packages in `MALICIOUS_NPM_VERSIONS` to clean versions.

---

*Need IR help? Intrudify specialises in supply chain compromise response.*  
*Contact: marc@intrudify.com*
