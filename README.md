# Mini Shai-Hulud Scanner

Detection scripts for the **Mini Shai-Hulud** npm/PyPI supply chain worm (NHS CC-4781, CVE-2026-45321, GHSA-g7cv-rxg3-hmpx, CVSS 9.6 Critical). Covers 170+ compromised npm packages across TanStack, UiPath, SAP @cap-js, and more, plus PyPI packages and all known persistence/C2 indicators.

Three scripts: Python, Bash, PowerShell -> covering the same 19 checks. Run whichever fits your environment.

---

## CRITICAL: Read before you scan

**RANSOM TOKEN WARNING.**
The worm plants an npm token named `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`. A background daemon (`gh-token-monitor`) polls `api.github.com/user` every 60 seconds. If the token is revoked, the daemon executes `rm -rf ~/` (Linux/macOS) or the Windows equivalent.

**Remediation order do not skip steps:**
1. Network-isolate the machine first (pull the cable or disable the NIC)
2. Take a forensic image
3. Revoke the token from a **separate admin account** that is not on the compromised machine
4. Only then begin cleanup

---

## What is checked

| # | Check |
|---|---|
| 1 | npm packages -- 170+ compromised exact versions (TanStack, UiPath, SAP @cap-js, etc.) |
| 2 | PyPI packages -- litellm, telnyx, lightning, mistralai, guardrails-ai |
| 3 | Persistence -- macOS LaunchAgent, Linux systemd, Windows Scheduled Task, HKCU Run key |
| 4 | Persistence -- Claude Code SessionStart hook, VS Code folderOpen task |
| 5 | Payload files on disk with SHA-256 hash verification (11 known-bad hashes) |
| 6 | C2 domains in /etc/hosts, proxy env vars, WinHTTP proxy |
| 7 | DNS resolution of 11 tracked C2 domains |
| 8 | Active TCP connections to 5 tracked C2 IPs |
| 9 | `package.json` optionalDependencies `github:tanstack/router` injection |
| 10 | `package.json` prepare script `bun run tanstack_runner.js` injection |
| 11 | Malicious `.github/workflows/codeql_analysis.yml` and `format-check.yml` |
| 12 | Git log -- attacker exfil commits (`claude@users.noreply.github.com`) |
| 13 | Dune-themed worm propagation branches + `dependabout/` typosquat |
| 14 | npm token audit -- RANSOM TOKEN detection |
| 15 | Shell/PowerShell history IOC scan |
| 16 | CI environment credential leakage (GitHub Actions) |
| 17 | Git remotes -- attacker accounts and C2 domains |
| 18 | Secondary persistence -- sysmon/pgmon service disguise, `litellm_init.pth`, Kubernetes DaemonSet |
| 19 | TeamPCP malware identification strings in config dirs |

---

## Python -- `scan_cc4781.py`

**Requires:** Python 3.9+. No external packages.

```bash
python3 scan_cc4781.py
python3 scan_cc4781.py --json          # machine-readable JSON output
python3 scan_cc4781.py --deep          # recursively find all node_modules under CWD
python3 scan_cc4781.py --npm-dir /path/to/node_modules
```

Runs on Linux, macOS, and Windows (WSL or native Python).

---

## Bash -- `scan_cc4781.sh`

**Requires:** Bash 4+. Optional: `python3` (for JSON parsing), `dig`/`nslookup`, `ss`, `kubectl`.

```bash
chmod +x scan_cc4781.sh
./scan_cc4781.sh
./scan_cc4781.sh --json
./scan_cc4781.sh --deep
./scan_cc4781.sh --npm-dir /path/to/node_modules
```

Designed for Linux and macOS CI runners, developer workstations, and Docker containers.

---

## PowerShell -- `scan_cc4781.ps1`

**Requires:** PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform). No modules required.

```powershell
.\scan_cc4781.ps1
.\scan_cc4781.ps1 -Json
.\scan_cc4781.ps1 -Deep
.\scan_cc4781.ps1 -NpmDir C:\projects\myapp\node_modules
```

Checks Windows-specific persistence (Scheduled Task, HKCU Run key, Startup folder) in addition to all cross-platform checks.

If execution policy blocks the script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scan_cc4781.ps1
```

---

## Output

**Text mode (default):** colour-coded findings by severity.

```
[CRITICAL] npm-compromised-package: @tanstack/react-router@1.169.5 is a confirmed-malicious version
  -> /home/user/project/node_modules/@tanstack/react-router/package.json

[HIGH] c2-dns-resolves: git-tanstack.com resolves to 83.142.209.194 -- C2 reachable from this host

RESULT: 1 CRITICAL / 2 HIGH findings
ISOLATE machine from network FIRST, THEN rotate credentials.
```

**JSON mode (`--json` / `-Json`):** single JSON object with `host` and `findings` array. Suitable for piping to a SIEM or SOAR.

---

## Affected package waves

| Wave | Date | Packages | Attacker publisher |
|---|---|---|---|
| TanStack | May 2026 | 43 `@tanstack/*` packages | `voicproducoes` |
| UiPath/JFrog | May 2026 | 66 `@uipath/*` packages | `voicproducoes` / `zblgg` |
| SAP @cap-js | April 2026 | `@cap-js/db-service`, `@cap-js/sqlite`, `@cap-js/postgres`, `mbt` | `cloudmtabot` |
| PyPI | Feb--April 2026 | `litellm`, `telnyx`, `lightning`, `mistralai`, `guardrails-ai` | various |

---

## IOC sources

Aggregated from (as of 2026-05-13): GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity, Socket.dev, Wiz Threat Research, Snyk, Aikido Security, Orca Security, Mend.io.

Detection rules: Sigma `5299fadf-f228-4526-8274-251db1960be9` (Shai-Hulud Malicious Bun Execution), Palo Alto ATP signature `87120`.

---

## References

- https://digital.nhs.uk/cyber-alerts/2026/cc-4781
- https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- https://nvd.nist.gov/vuln/detail/CVE-2026-45321
- https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- https://research.jfrog.com/post/shai-hulud-here-we-go-again/
- https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised

---

## Suggested GitHub repository name

**`mini-shai-hulud-scanner`**

Matches the campaign name exactly as used in every public advisory. People searching "mini shai hulud npm" or "shai hulud supply chain scanner" will land directly on it.

Alternatives if taken: `cc4781-scanner`, `npm-supply-chain-worm-scanner`, `teamPCP-ioc-scanner`.

---

*Need help containing an active supply chain compromise? Intrudify provides AI-powered pentesting and IR for npm/PyPI worm campaigns, CI/CD pipeline hijacks, and GitHub Actions OIDC token abuse. Contact: marc@intrudify.com*
