#!/usr/bin/env python3
"""
CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner
NHS Cyber Alert CC-4781  |  CVE-2026-45321  |  GHSA-g7cv-rxg3-hmpx
TeamPCP threat group  |  Published 12 May 2026

IOC sources (aggregated 2026-05-13):
  GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity, Socket.dev,
  Wiz Threat Research, Snyk, Aikido Security, Orca Security, Mend.io

Checks:
  1.  npm compromised versions (insider-channel + stable-channel, 170+ packages)
  2.  PyPI compromised packages
  3.  Persistence implants (macOS LaunchAgent, Linux systemd, Claude Code hook,
      VS Code folderOpen task)
  4.  Payload artefacts on disk with SHA-256 hash verification
  5.  C2 indicators in /etc/hosts, proxy env, DNS
  6.  Active connections to C2 IPs (/proc/net, ss)
  7.  package.json optionalDependencies github: injection
  8.  package.json prepare script injection (bun run tanstack_runner.js pattern)
  9.  Malicious .github/workflows/codeql_analysis.yml
 10.  Git log - attacker exfil commits (claude@users.noreply.github.com)
 11.  Dune-themed worm propagation branches
 12.  npm token audit + RANSOM TOKEN detection
 13.  Shell history IOC scan
 14.  CI environment credential leakage
 15.  SLSA BL3 provenance bypass warning

CRITICAL WARNINGS:
  - RANSOM TOKEN: npm token with description
    'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner'
    polls api.github.com/user every 60 s. A 40x response triggers rm -rf ~/ .
    ISOLATE MACHINE FROM NETWORK BEFORE revoking any npm tokens.
  - Dead-man's switch: gh-token-monitor daemon polls api.github.com every 60s
    and executes machine wipe if token is revoked.

Usage:
  python3 scan_cc4781.py [--json] [--deep] [--npm-dir /path/to/node_modules]
"""

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

# IOC DATA
# Sources: GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity,
#          Socket.dev, Wiz, Snyk, Aikido, Orca, Mend.io (aggregated 2026-05-13)

MALICIOUS_NPM_VERSIONS: dict[str, set[str]] = {

    # @tanstack (42 packages, all confirmed by GHSA-g7cv-rxg3-hmpx)
    "@tanstack/arktype-adapter":              {"1.166.12", "1.166.15"},
    "@tanstack/eslint-plugin-router":         {"1.161.9", "1.161.12"},
    "@tanstack/eslint-plugin-start":          {"0.0.4", "0.0.7"},
    "@tanstack/history":                      {"1.161.9", "1.161.12"},
    "@tanstack/nitro-v2-vite-plugin":         {"1.154.12", "1.154.15"},
    "@tanstack/react-router":                 {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.169.5", "1.169.8"},
    "@tanstack/react-router-devtools":        {"1.166.16", "1.166.19"},
    "@tanstack/react-router-ssr-query":       {"1.166.15", "1.166.18"},
    "@tanstack/react-start":                  {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.167.68", "1.167.71"},
    "@tanstack/react-start-client":           {"1.166.51", "1.166.54"},
    "@tanstack/react-start-rsc":              {"0.0.47", "0.0.50"},
    "@tanstack/react-start-server":           {"1.166.55", "1.166.58"},
    "@tanstack/router-cli":                   {"1.166.46", "1.166.49"},
    "@tanstack/router-core":                  {"1.169.5", "1.169.8"},
    "@tanstack/router-devtools":              {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.166.16", "1.166.19"},
    "@tanstack/router-devtools-core":         {"1.167.6", "1.167.9"},
    "@tanstack/router-generator":             {"1.166.45", "1.166.48"},
    "@tanstack/router-plugin":                {"1.167.38", "1.167.41"},
    "@tanstack/router-ssr-query-core":        {"1.168.3", "1.168.6"},
    "@tanstack/router-utils":                 {"1.161.11", "1.161.14"},
    "@tanstack/router-vite-plugin":           {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.166.53", "1.166.56"},
    "@tanstack/solid-router":                 {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.169.5", "1.169.8"},
    "@tanstack/solid-router-devtools":        {"1.166.16", "1.166.19"},
    "@tanstack/solid-router-ssr-query":       {"1.166.15", "1.166.18"},
    "@tanstack/solid-start":                  {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.167.65", "1.167.68"},
    "@tanstack/solid-start-client":           {"1.166.50", "1.166.53"},
    "@tanstack/solid-start-server":           {"1.166.54", "1.166.57"},
    "@tanstack/start":                        {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921"},
    "@tanstack/start-client-core":            {"1.168.5", "1.168.8"},
    "@tanstack/start-fn-stubs":               {"1.161.9", "1.161.12"},
    "@tanstack/start-plugin-core":            {"1.169.23", "1.169.26"},
    "@tanstack/start-server-core":            {"1.167.33", "1.167.36"},
    "@tanstack/start-static-server-functions":{"1.166.44", "1.166.47"},
    "@tanstack/start-storage-context":        {"1.166.38", "1.166.41"},
    "@tanstack/valibot-adapter":              {"1.166.12", "1.166.15"},
    "@tanstack/virtual-file-routes":          {"1.161.10", "1.161.13"},
    "@tanstack/vue-router":                   {"0.0.1-insiders.20260511180920",
                                               "0.0.1-insiders.20260511180921",
                                               "1.169.5", "1.169.8"},
    "@tanstack/vue-router-devtools":          {"1.166.16", "1.166.19"},
    "@tanstack/vue-router-ssr-query":         {"1.166.15", "1.166.18"},
    "@tanstack/vue-start":                    {"1.167.61", "1.167.64"},
    "@tanstack/vue-start-client":             {"1.166.46", "1.166.49"},
    "@tanstack/vue-start-server":             {"1.166.50", "1.166.53"},
    "@tanstack/zod-adapter":                  {"1.166.12", "1.166.15"},

    # @uipath (56-66 packages; source: JFrog Security Research)
    "@uipath/access-policy-sdk":              {"0.3.1"},
    "@uipath/access-policy-tool":             {"0.3.1"},
    "@uipath/admin-tool":                     {"0.1.1"},
    "@uipath/agent-sdk":                      {"1.0.2"},
    "@uipath/agent-tool":                     {"1.0.1"},
    "@uipath/agent.sdk":                      {"0.0.18"},
    "@uipath/agent-x":                        {"1.0.1"},
    "@uipath/aops-policy-tool":               {"0.3.1"},
    "@uipath/ap-chat":                        {"1.5.7"},
    "@uipath/api-workflow-tool":              {"1.0.1"},
    "@uipath/apollo-core":                    {"1.1.2", "5.9.2"},
    "@uipath/apollo-react":                   {"4.24.5"},
    "@uipath/apollo-wind":                    {"2.16.2"},
    "@uipath/auth":                           {"1.0.1"},
    "@uipath/case-tool":                      {"1.0.1"},
    "@uipath/cli":                            {"1.0.1", "1.0.5"},
    "@uipath/codedagent-tool":                {"1.0.1"},
    "@uipath/codedagents-tool":               {"0.1.12"},
    "@uipath/codedapp-tool":                  {"1.0.1"},
    "@uipath/common":                         {"1.0.1"},
    "@uipath/context-grounding-tool":         {"0.1.1"},
    "@uipath/data-fabric-tool":               {"1.0.2"},
    "@uipath/docsai-tool":                    {"1.0.1"},
    "@uipath/filesystem":                     {"1.0.1"},
    "@uipath/flow-tool":                      {"1.0.2"},
    "@uipath/functions-tool":                 {"1.0.1"},
    "@uipath/gov-tool":                       {"0.3.1"},
    "@uipath/identity-tool":                  {"0.1.1"},
    "@uipath/insights-sdk":                   {"1.0.1"},
    "@uipath/insights-tool":                  {"1.0.1"},
    "@uipath/integrationservice-sdk":         {"1.0.2"},
    "@uipath/integrationservice-tool":        {"1.0.2"},
    "@uipath/llmgw-tool":                     {"1.0.1"},
    "@uipath/maestro-sdk":                    {"1.0.1"},
    "@uipath/maestro-tool":                   {"1.0.1"},
    "@uipath/orchestrator-tool":              {"1.0.1"},
    "@uipath/packager-tool-apiworkflow":      {"0.0.19"},
    "@uipath/packager-tool-bpmn":             {"0.0.9"},
    "@uipath/packager-tool-case":             {"0.0.9"},
    "@uipath/packager-tool-connector":        {"0.0.19"},
    "@uipath/packager-tool-flow":             {"0.0.19"},
    "@uipath/packager-tool-functions":        {"0.1.1"},
    "@uipath/packager-tool-webapp":           {"1.0.6"},
    "@uipath/packager-tool-workflowcompiler": {"0.0.16"},
    "@uipath/packager-tool-workflowcompiler-browser": {"0.0.34"},
    "@uipath/platform-tool":                  {"1.0.1"},
    "@uipath/project-packager":               {"1.1.16"},
    "@uipath/resource-tool":                  {"1.0.1"},
    "@uipath/resourcecatalog-tool":           {"0.1.1"},
    "@uipath/resources-tool":                 {"0.1.11"},
    "@uipath/robot":                          {"0.11.2", "1.3.4"},
    "@uipath/rpa-legacy-tool":                {"1.0.1"},
    "@uipath/rpa-tool":                       {"0.9.5"},
    "@uipath/solution-packager":              {"0.0.35"},
    "@uipath/solution-tool":                  {"1.0.1"},
    "@uipath/solutionpackager-sdk":           {"1.0.11"},
    "@uipath/solutionpackager-tool-core":     {"0.0.34"},
    "@uipath/tasks-tool":                     {"1.0.1"},
    "@uipath/telemetry":                      {"0.0.7"},
    "@uipath/test-manager-tool":              {"1.0.2"},
    "@uipath/tool-workflowcompiler":          {"0.0.12"},
    "@uipath/traces-tool":                    {"1.0.1"},
    "@uipath/ui-widgets-multi-file-upload":   {"1.0.1"},
    "@uipath/uipath-python-bridge":           {"1.0.1"},
    "@uipath/vertical-solutions-tool":        {"1.0.1"},
    "@uipath/vss":                            {"0.1.6"},
    "@uipath/widget.sdk":                     {"1.2.3"},

    # @mistralai namespace
    "@mistralai/mistralai":                   {"1.4.3", "1.4.4", "1.5.0",
                                               "2.2.2", "2.2.3", "2.2.4"},
    "@mistralai/mistralai-azure":             {"1.5.0", "1.7.1", "1.7.2", "1.7.3"},
    "@mistralai/mistralai-gcp":               {"1.5.0", "1.7.1", "1.7.2", "1.7.3"},

    # @opensearch-project namespace
    "@opensearch-project/opensearch":         {"3.5.3", "3.6.2", "3.7.0", "3.8.0"},

    # @squawk namespace (aviation data; ~23 packages; specific versions for 3)
    "@squawk/mcp":                            {"0.9.5"},
    "@squawk/weather":                        {"0.5.10"},
    "@squawk/flightplan":                     {"0.5.6"},

    # @draftlab / @draftauth namespace
    "@draftlab/auth":                         {"0.24.1", "0.24.2"},
    "@draftlab/auth-router":                  {"0.5.1", "0.5.2"},
    "@draftlab/db":                           {"0.16.1", "0.16.2"},
    "@draftauth/client":                      {"0.2.1", "0.2.2"},
    "@draftauth/core":                        {"0.13.1", "0.13.2"},

    # @beproduct namespace
    "@beproduct/nestjs-auth":                 {f"0.1.{i}" for i in range(2, 20)},

    # @ml-toolkit-ts namespace
    "@ml-toolkit-ts/preprocessing":           {"1.0.2", "1.0.3"},
    "@ml-toolkit-ts/xgboost":                 {"1.0.3", "1.0.4"},

    # @mesadev namespace
    "@mesadev/rest":                          {"0.28.3"},
    "@mesadev/saguaro":                       {"0.4.22"},
    "@mesadev/sdk":                           {"0.28.3"},

    # @dirigible-ai namespace
    "@dirigible-ai/sdk":                      {"0.6.2", "0.6.3"},

    # @taskflow-corp namespace
    "@taskflow-corp/cli":                     {f"0.1.{i}" for i in range(24, 30)},

    # @tolka namespace
    "@tolka/cli":                             {"1.0.2", "1.0.3", "1.0.4", "1.0.6"},

    # @supersurkhet namespace
    "@supersurkhet/cli":                      {f"0.0.{i}" for i in range(2, 8)},
    "@supersurkhet/sdk":                      {f"0.0.{i}" for i in range(2, 8)},

    # SAP @cap-js / mbt wave (April 29, 2026 -- malicious publisher: cloudmtabot)
    "@cap-js/db-service":                     {"2.10.1"},
    "@cap-js/sqlite":                         {"2.2.2"},
    "@cap-js/postgres":                       {"2.2.2"},
    "mbt":                                    {"1.2.48"},

    # Unscoped packages
    "intercom-client":                        {"7.0.4"},
    "lightning":                              {"2.6.2", "2.6.3"},
    "safe-action":                            {"0.8.3", "0.8.4"},
    "cmux-agent-mcp":                         {f"0.1.{i}" for i in range(3, 9)},
    "git-git-git":                            {"1.0.8", "1.0.9", "1.0.10", "1.0.12"},
    "git-branch-selector":                    {"1.3.3", "1.3.4", "1.3.5", "1.3.7"},
    "nextmove-mcp":                           {"0.1.3", "0.1.4", "0.1.5", "0.1.7"},
    "agentwork-cli":                          {"0.1.4", "0.1.5"},
    "ml-toolkit-ts":                          {"1.0.4", "1.0.5"},
    "wot-api":                                {"0.8.1", "0.8.2", "0.8.4"},
    "cross-stitch":                           {"1.1.3", "1.1.4", "1.1.6"},
    "ts-dna":                                 {"3.0.1", "3.0.2", "3.0.4"},
}

MALICIOUS_PYPI_VERSIONS: dict[str, set[str]] = {
    "guardrails-ai": {"0.10.1"},
    "mistralai":     {"2.4.6"},
    "litellm":       {"1.82.7", "1.82.8"},   # LiteLLM wave (Feb 2026)
    "telnyx":        {"4.87.1", "4.87.2"},   # Telnyx wave (Feb 2026)
    "lightning":     {"2.6.2", "2.6.3"},     # PyTorch Lightning (April 2026)
}

# C2 infrastructure
C2_DOMAINS = {
    # Mini Shai-Hulud (TanStack wave, May 2026)
    "git-tanstack.com",              # worm command server / typosquat
    "filev2.getsession.org",         # Session Protocol CDN exfil (primary)
    "api.masscan.cloud",             # direct secret exfiltration
    "seed1.getsession.org",          # Session seed node (TLS cert pinned, expires 2033)
    "seed2.getsession.org",          # Session seed node
    "seed3.getsession.org",          # Session seed node
    # Earlier TeamPCP waves (CanisterWorm / Trivy / Checkmarx)
    "scan.aquasecurtiy.org",         # Trivy wave typosquat (note misspelling)
    "checkmarx.zone",                # KICS/Checkmarx wave C2
    "models.litellm.cloud",          # LiteLLM wave exfiltration
    "recv.hackmoltrepeat.com",       # PAT exfiltration (Feb 2026)
    "nsa.cat",                       # TeamPCP VPS
}
C2_IPS = {
    "83.142.209.194",    # TanStack wave
    "83.142.209.203",    # WAV steganography payload server
    "45.148.10.212",     # scan.aquasecurtiy.org (Trivy wave)
    "46.151.182.203",    # TeamPCP infrastructure
    "23.142.184.129",    # TeamPCP infrastructure
}

# Known-malicious SHA-256 hashes
# Sources: JFrog Security Research, Wiz, Armorcode, StepSecurity
KNOWN_BAD_SHA256: dict[str, str] = {
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c":
        "router_init.js -- stage-1 loader (2,341,681 bytes, single-line)",
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96":
        "tanstack_runner.js -- worm engine (2,339,346 bytes, 3-layer obfuscated JS)",
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b":
        "@tanstack/setup package.json -- attacker publish-stage manifest",
    "2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe27678b2df360bd90d3df":
        "setup.mjs -- Bun loader / preinstall script (5,047 bytes)",
    "29c729852fce5a53e30a1541d9fec79c915b2e13f1eda94a5978cf0aae0d88d9":
        "npm payload variant #1 (non-TanStack packages)",
    "d4a2086ea18f5e39cd867b8b06918a524eabb21d45ea98aad07357b98173458a":
        "npm payload variant #2 (non-TanStack packages)",
    "2a314ea8be337e1ca9ec833ed13ed854d9fd38bce0a519cf288f3bec8d9e6f30":
        "PyPI __init__.py -- Python ecosystem payload",
    "5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b":
        "transformers.pyz -- PyPI zipapp payload",
    # SAP @cap-js wave (April 2026)
    "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34":
        "setup.mjs (SAP @cap-js wave, identical across all 4 SAP packages)",
    "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7":
        "embedded /proc/mem dumper (SAP wave -- extracts runner secrets from memory)",
    # Trivy wave
    "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a":
        "entrypoint.sh -- Trivy action payload (204 lines, 17,592 bytes)",
}

# Payload filenames (survives npm uninstall in cache dirs)
PAYLOAD_FILENAMES = {
    "router_runtime.js",   # Bun persistence payload (.claude/)
    "router_init.js",      # stage-1 loader injected into package
    "tanstack_runner.js",  # 2.3 MB obfuscated worm engine
    "bun_environment.js",  # Sigma rule 5299fadf: Shai-Hulud Malicious Bun Execution
    "setup.mjs",           # shared setup script (.claude/ and .vscode/)
    "transformers.pyz",    # Python zipapp payload (PyPI variant)
    "gh-token-monitor",    # daemon binary / shell script
    "execution.js",        # SAP wave payload (11.6 MB obfuscated)
    "litellm_init.pth",    # Python .pth hook -- auto-executes on ANY python invocation
    "kamikaze.sh",         # destructive shell payload
    "hangup.wav",          # WAV steganography container (Windows)
    "ringtone.wav",        # WAV steganography container (Linux)
    "sysmon.py",           # persistence disguised as system telemetry
}

# Attacker GitHub artefacts
ATTACKER_GITHUB_ACCOUNTS  = {
    "voicproducoes",     # main account (ID 269549300, created 2026-03-19)
    "zblgg",             # fork alias used to evade fork detection
    "cloudmtabot",       # SAP @cap-js wave malicious publisher
    "MegaGame10418",     # exploited Feb 2026 PwnRequest, stole aqua-bot PAT
    "hackerbot-claw",    # automated scanning bot (created 2026-02-20)
}
ATTACKER_FORK_REPO        = "zblgg/configuration"           # fork used to evade fork detection
ATTACKER_COMMIT           = "79ac49eedf774dd4b0cfa308722bc463cfe5885c"
ATTACKER_EXFIL_EMAIL      = "claude@users.noreply.github.com"
ATTACKER_EXFIL_MSGS       = {"chore: update dependencies", "EveryBoiWeBuildIsAWormyBoi"}
DEAD_DROP_REPO_NAMES      = {"tpcp-docs", "docs-tpcp"}
DEAD_DROP_REPO_DESCS      = {
    "A Mini Shai-Hulud has Appeared",
    "Shai-Hulud: Here We Go Again",
    "PUSH UR T3MPRR",
}
MALWARE_STRINGS           = {
    "svksjrhjkcejg",                      # PBKDF2 salt (TanStack wave)
    "OhNoWhatsGoingOnWithGitHub",         # P2P token dead-drop magic string
    "__DAEMONIZED",                        # daemonization env var marker
    "TeamPCP Cloud stealer",              # attacker self-attribution
    "ctf-scramble-v2",                    # custom cipher identifier (SAP wave)
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
    "EveryBoiWeBuildIsAWormyBoi",
    "Exiting as russian language detected",  # CIS evasion string
}
SYSMON_SERVICE_PATHS = [
    Path.home() / ".config/systemd/user/sysmon.service",
    Path.home() / ".config/systemd/user/pgmon.service",
    Path.home() / ".config/sysmon/sysmon.py",
    Path.home() / ".local/share/pgmon/service.py",
    Path("/etc/systemd/system/sysmon.service"),
]
ATTACKER_OPTDEP_REF       = f"github:tanstack/router#{ATTACKER_COMMIT}"

# RANSOM TOKEN -- see module docstring for wipe-trigger mechanics
RANSOM_TOKEN_DESCRIPTION  = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"

# Prepare-script injection pattern
MALICIOUS_PREPARE_PATTERN = re.compile(r"bun run tanstack_runner\.js", re.IGNORECASE)

# Persistence paths
MACOS_LAUNCHAGENT  = Path.home() / "Library/LaunchAgents/com.user.gh-token-monitor.plist"
LINUX_SYSTEMD_UNIT = Path.home() / ".config/systemd/user/gh-token-monitor.service"

SURVIVOR_DIRS = [
    Path.home() / ".claude",
    Path.home() / ".vscode",
    Path.home() / ".cache/node",
    Path.home() / ".npm/_npx",
    Path.home() / ".pnpm-store",
    Path.home() / ".config/gh-token-monitor",
]

# Dune-themed dead-drop pattern (expanded wordlist from attacker repos)
DUNE_PATTERN = re.compile(
    r"(shai.?hulud|here.we.go.again|lisan.al.gaib|muad.?dib|fremkit|sandworm|"
    r"atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|"
    r"kanly|kralizec|lasgun|laza|melange|mentat|navigator|ornithopter|phibian|"
    r"powindah|prana|prescient|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|"
    r"thumper|tleilaxu)",
    re.IGNORECASE,
)
DUNE_BRANCH_PREFIX = "dependabot/github_actions/format/"

# COLOUR HELPERS
RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

use_json = False
findings: list[dict] = []


def emit(severity: str, category: str, detail: str, path: str = "") -> None:
    record: dict = {"severity": severity, "category": category, "detail": detail}
    if path:
        record["path"] = path
    findings.append(record)
    if not use_json:
        colour = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
        tag = f"{colour}{BOLD}[{severity}]{RESET}"
        loc = f"  -> {path}" if path else ""
        print(f"{tag} {BOLD}{category}{RESET}: {detail}{loc}")


def info(msg: str) -> None:
    if not use_json:
        print(f"{CYAN}[INFO]{RESET} {msg}")


def ok(msg: str) -> None:
    if not use_json:
        print(f"{GREEN}[OK]{RESET}   {msg}")


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# CHECK 1: npm packages
def get_node_modules_dirs(npm_dir_arg: Optional[str], deep: bool) -> list[Path]:
    dirs: list[Path] = []
    if npm_dir_arg:
        p = Path(npm_dir_arg)
        if p.is_dir():
            dirs.append(p)
        return dirs
    rc, out, _ = run(["npm", "root", "-g"])
    if rc == 0 and out.strip():
        gp = Path(out.strip())
        if gp.is_dir():
            dirs.append(gp)
    local = Path.cwd() / "node_modules"
    if local.is_dir():
        dirs.append(local)
    if deep:
        for nm in Path.cwd().rglob("node_modules"):
            if nm.is_dir() and nm not in dirs:
                dirs.append(nm)
    return dirs


def check_npm_package(nm_dir: Path, pkg: str, bad_versions: set[str]) -> None:
    parts = pkg.split("/")
    pkg_path = nm_dir.joinpath(*parts) / "package.json"
    if not pkg_path.exists():
        return
    try:
        with open(pkg_path) as f:
            data = json.load(f)
        version = data.get("version", "")
        if version in bad_versions:
            emit("CRITICAL", "npm-compromised-package",
                 f"{pkg}@{version} is a confirmed-malicious version",
                 str(pkg_path))
    except Exception:
        pass


def scan_npm(npm_dir_arg: Optional[str], deep: bool) -> list[Path]:
    info(f"Checking {len(MALICIOUS_NPM_VERSIONS)} npm packages for compromised versions ...")
    nm_dirs = get_node_modules_dirs(npm_dir_arg, deep)
    if not nm_dirs:
        info("No node_modules found -- skipping npm scan")
        return nm_dirs
    for nm_dir in nm_dirs:
        for pkg, bad_vers in MALICIOUS_NPM_VERSIONS.items():
            check_npm_package(nm_dir, pkg, bad_vers)
    return nm_dirs


def scan_lockfile() -> None:
    info("Scanning lockfiles for compromised package entries ...")
    lockfiles = (list(Path.cwd().rglob("package-lock.json")) +
                 list(Path.cwd().rglob("pnpm-lock.yaml")) +
                 list(Path.cwd().rglob("yarn.lock")))
    for lf in lockfiles:
        try:
            content = lf.read_text(errors="replace")
            for pkg, bad_vers in MALICIOUS_NPM_VERSIONS.items():
                for bv in bad_vers:
                    if f'"{pkg}"' in content and bv in content:
                        emit("HIGH", "lockfile-bad-version",
                             f"{pkg}@{bv} referenced in lockfile", str(lf))
        except Exception:
            pass


# CHECK 2: PyPI
def scan_pypi() -> None:
    info("Checking installed PyPI packages ...")
    try:
        import importlib.metadata as meta
        for dist_name, bad_vers in MALICIOUS_PYPI_VERSIONS.items():
            try:
                ver = meta.version(dist_name)
                if ver in bad_vers:
                    emit("CRITICAL", "pypi-compromised-package",
                         f"{dist_name}=={ver} is a known-malicious version")
                else:
                    ok(f"{dist_name}=={ver} installed (version not flagged)")
            except meta.PackageNotFoundError:
                pass
    except ImportError:
        rc, out, _ = run([sys.executable, "-m", "pip", "list", "--format=json"])
        if rc == 0:
            try:
                for p in json.loads(out):
                    name = p.get("name", "").lower()
                    ver  = p.get("version", "")
                    if name in MALICIOUS_PYPI_VERSIONS and ver in MALICIOUS_PYPI_VERSIONS[name]:
                        emit("CRITICAL", "pypi-compromised-package",
                             f"{name}=={ver} is a known-malicious version")
            except Exception:
                pass


# CHECK 3: Persistence
def scan_persistence() -> None:
    info("Checking for gh-token-monitor persistence implants ...")
    sys_name = platform.system()
    if sys_name == "Darwin":
        if MACOS_LAUNCHAGENT.exists():
            emit("CRITICAL", "persistence-daemon",
                 "macOS LaunchAgent found -- stop daemon BEFORE revoking any npm tokens "
                 "(ransom wipe triggers on token revocation)",
                 str(MACOS_LAUNCHAGENT))
        else:
            ok("macOS LaunchAgent not present")
    elif sys_name == "Linux":
        if LINUX_SYSTEMD_UNIT.exists():
            emit("CRITICAL", "persistence-daemon",
                 "Linux systemd user unit found -- "
                 "systemctl --user stop gh-token-monitor BEFORE revoking npm tokens",
                 str(LINUX_SYSTEMD_UNIT))
        else:
            ok("Linux systemd user unit not present")
        etc_unit = Path("/etc/systemd/system/gh-token-monitor.service")
        if etc_unit.exists():
            emit("CRITICAL", "persistence-daemon",
                 "System-wide systemd unit found", str(etc_unit))

    # Claude Code SessionStart hook
    claude_settings = Path.home() / ".claude" / "settings.json"
    if claude_settings.exists():
        try:
            data = json.loads(claude_settings.read_text(errors="replace"))
            hooks = data.get("hooks", {}).get("SessionStart", [])
            for hook in hooks:
                cmd = str(hook.get("command", ""))
                if "setup.mjs" in cmd or "tanstack_runner" in cmd or "router_runtime" in cmd:
                    emit("CRITICAL", "persistence-claude-hook",
                         f"Malicious Claude Code SessionStart hook found: {cmd}",
                         str(claude_settings))
        except Exception:
            pass

    # VS Code folderOpen task
    vscode_tasks = Path.cwd() / ".vscode" / "tasks.json"
    if vscode_tasks.exists():
        try:
            content = vscode_tasks.read_text(errors="replace")
            if "setup.mjs" in content or "tanstack_runner" in content:
                emit("CRITICAL", "persistence-vscode-task",
                     "Malicious VS Code folderOpen task found -- triggers on folder open",
                     str(vscode_tasks))
        except Exception:
            pass

    rc, out, _ = run(["pgrep", "-a", "gh-token-monitor"])
    if rc == 0 and out.strip():
        emit("CRITICAL", "persistence-process",
             "gh-token-monitor process is running -- isolate machine BEFORE revoking tokens",
             out.strip())
    else:
        ok("gh-token-monitor process not detected")


# CHECK 4: Payload files + hash verification
def scan_payload_files() -> None:
    info("Searching for payload artefacts and verifying SHA-256 ...")
    found_any = False
    search_roots = [Path.home(), Path.cwd()] + SURVIVOR_DIRS
    seen: set[Path] = set()
    for root in search_roots:
        if not root.exists() or root in seen:
            continue
        seen.add(root)
        for fname in PAYLOAD_FILENAMES:
            for match in root.rglob(fname):
                try:
                    if not match.is_file():
                        continue
                    digest = sha256_file(match)
                    if digest in KNOWN_BAD_SHA256:
                        emit("CRITICAL", "payload-confirmed-malicious",
                             f"CONFIRMED MALICIOUS: {fname} (sha256={digest}) -- "
                             f"{KNOWN_BAD_SHA256[digest]}",
                             str(match))
                    else:
                        size = match.stat().st_size
                        size_warn = " (SUSPICIOUS SIZE: ~2.3 MB worm engine)" if size > 2_000_000 else ""
                        emit("HIGH", "payload-artefact",
                             f"Payload filename {fname} found (sha256={digest}, "
                             f"size={size:,} bytes){size_warn}",
                             str(match))
                    found_any = True
                except PermissionError:
                    pass
    if not found_any:
        ok("No payload artefact filenames found")


# CHECK 5: C2 indicators
def scan_c2_indicators() -> None:
    info("Checking for C2 domain indicators ...")
    hosts_path = Path("/etc/hosts")
    if hosts_path.exists():
        try:
            content = hosts_path.read_text()
            for dom in C2_DOMAINS:
                if dom in content:
                    emit("HIGH", "c2-in-hosts", f"{dom} present in /etc/hosts")
        except PermissionError:
            pass
    for var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
        val = os.environ.get(var, "")
        for dom in C2_DOMAINS:
            if dom in val:
                emit("HIGH", "c2-in-proxy-env", f"{dom} referenced in ${var}")
    for dom in C2_DOMAINS:
        try:
            ip = socket.gethostbyname(dom)
            emit("HIGH", "c2-dns-resolves",
                 f"{dom} resolves to {ip} -- C2 reachable from this host")
        except socket.gaierror:
            ok(f"{dom} does not resolve")


def scan_c2_connections() -> None:
    info("Checking for active connections to C2 infrastructure ...")
    if platform.system() != "Linux":
        return
    rc, out, _ = run(["ss", "-tnp"])
    if rc == 0:
        for ip in C2_IPS:
            if ip in out:
                emit("CRITICAL", "active-c2-connection",
                     f"Active connection to C2 IP {ip} (ss)")
    for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            content = Path(proto_file).read_text()
            for ip in C2_IPS:
                parts = [int(x) for x in ip.split(".")]
                hex_ip = "%08X" % (parts[3] << 24 | parts[2] << 16 | parts[1] << 8 | parts[0])
                if hex_ip in content:
                    emit("CRITICAL", "active-c2-connection",
                         f"Connection to C2 IP {ip} in {proto_file}")
        except Exception:
            pass


# CHECK 6: optionalDependencies injection
def scan_optdeps_injection() -> None:
    info("Scanning package.json for attacker optionalDependencies injection ...")
    found = False
    for pkg_json in Path.cwd().rglob("package.json"):
        if "node_modules" in pkg_json.parts:
            continue
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            for dep, ref in (data.get("optionalDependencies") or {}).items():
                if isinstance(ref, str) and "github:tanstack/router" in ref:
                    emit("CRITICAL", "optdeps-github-injection",
                         f"optionalDependencies['{dep}'] = '{ref}' -- attacker injection pattern",
                         str(pkg_json))
                    found = True
                if isinstance(ref, str) and ATTACKER_COMMIT in ref:
                    emit("CRITICAL", "optdeps-attacker-commit",
                         f"optionalDependencies['{dep}'] contains attacker commit {ATTACKER_COMMIT}",
                         str(pkg_json))
                    found = True
        except Exception:
            pass
    if not found:
        ok("No malicious optionalDependencies github: references found")


# CHECK 7: prepare script injection
def scan_prepare_script() -> None:
    info("Scanning package.json prepare scripts for malicious Bun invocation ...")
    found = False
    for pkg_json in Path.cwd().rglob("package.json"):
        if "node_modules" in pkg_json.parts:
            continue
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            prepare = (data.get("scripts") or {}).get("prepare", "")
            if MALICIOUS_PREPARE_PATTERN.search(prepare):
                emit("CRITICAL", "malicious-prepare-script",
                     f"prepare script matches worm injection pattern: '{prepare}'",
                     str(pkg_json))
                found = True
            elif prepare and "bun run" in prepare and any(
                f in prepare for f in PAYLOAD_FILENAMES
            ):
                emit("HIGH", "suspicious-prepare-script",
                     f"prepare script invokes Bun with suspicious filename: '{prepare}'",
                     str(pkg_json))
                found = True
        except Exception:
            pass
    if not found:
        ok("No malicious prepare script patterns found")


# CHECK 8: Malicious workflow
def scan_advanced_persistence() -> None:
    """Check for secondary persistence: sysmon/pgmon disguise, litellm .pth hook, Kubernetes."""
    info("Checking for secondary persistence mechanisms (sysmon/pgmon/litellm/k8s) ...")
    # sysmon.service and pgmon.service disguise
    for p in SYSMON_SERVICE_PATHS:
        if p.exists():
            emit("CRITICAL", "persistence-sysmon-disguise",
                 f"Persistence service disguised as system telemetry found: {p.name} -- "
                 "TeamPCP uses 'System Telemetry Service' label to blend in",
                 str(p))
    # litellm_init.pth -- Python startup hook, auto-executes on any python invocation
    import site
    for sp in site.getsitepackages() if hasattr(site, "getsitepackages") else []:
        pth = Path(sp) / "litellm_init.pth"
        if pth.exists():
            emit("CRITICAL", "persistence-python-pth",
                 "litellm_init.pth found in Python site-packages -- "
                 "executes malicious code on EVERY Python invocation",
                 str(pth))
    # WAV steganography containers
    wav_files = {"hangup.wav", "ringtone.wav"}
    for root in [Path.home(), Path.cwd()]:
        for wf in wav_files:
            for match in root.rglob(wf):
                if match.is_file():
                    emit("HIGH", "wav-steganography",
                         f"WAV steganography container {wf} found -- "
                         "TeamPCP embeds base64-encoded payloads in WAV files",
                         str(match))
    # Kubernetes: check for malicious pods/DaemonSets (if kubectl is available)
    rc, out, _ = run(["kubectl", "get", "pods", "-n", "kube-system",
                      "--no-headers", "-o", "custom-columns=NAME:.metadata.name"],
                     timeout=10)
    if rc == 0 and out.strip():
        for line in out.splitlines():
            pod = line.strip()
            if pod.startswith("node-setup-"):
                emit("CRITICAL", "kubernetes-malicious-pod",
                     f"TeamPCP Kubernetes pod found: '{pod}' -- "
                     "worm deploys DaemonSet in kube-system as 'node-setup-{node_name}'")
    rc2, out2, _ = run(["kubectl", "get", "daemonsets", "-n", "kube-system",
                        "--no-headers", "-o", "custom-columns=NAME:.metadata.name"],
                       timeout=10)
    if rc2 == 0 and out2.strip():
        for line in out2.splitlines():
            ds = line.strip()
            if ds.startswith("host-provisioner"):
                emit("CRITICAL", "kubernetes-malicious-daemonset",
                     f"TeamPCP DaemonSet found: '{ds}' -- "
                     "worm uses host-provisioner-* for Kubernetes persistence")


def scan_malware_strings() -> None:
    """Scan common config/log files for unique TeamPCP malware strings."""
    info("Scanning files for unique TeamPCP malware identification strings ...")
    scan_paths = [Path.home() / ".claude", Path.home() / ".vscode",
                  Path.cwd() / ".github", Path.cwd() / ".claude",
                  Path.cwd() / ".vscode"]
    found = False
    for root in scan_paths:
        if not root.exists():
            continue
        for f in root.rglob("*"):
            if not f.is_file() or f.suffix in {".png", ".jpg", ".gif", ".ico"}:
                continue
            try:
                content = f.read_text(errors="replace")
                for sig in MALWARE_STRINGS:
                    if sig in content:
                        emit("CRITICAL", "malware-string-found",
                             f"TeamPCP malware string '{sig}' found in file",
                             str(f))
                        found = True
            except (PermissionError, OSError):
                pass
    if not found:
        ok("No TeamPCP malware identification strings found")


def scan_malicious_workflow() -> None:
    info("Checking for malicious .github/workflows files ...")
    # TanStack wave: codeql_analysis.yml | SAP wave: format-check.yml
    workflow_dir = Path.cwd() / ".github" / "workflows"
    malicious_wf_names = {"codeql_analysis.yml", "format-check.yml"}
    for wf_name in malicious_wf_names:
        workflow = workflow_dir / wf_name
        if not workflow.exists():
            continue
        try:
            content = workflow.read_text(errors="replace")
            c2_found = False
            for dom in C2_DOMAINS:
                if dom in content:
                    emit("CRITICAL", "malicious-workflow",
                         f"{wf_name} contains C2 domain '{dom}' -- "
                         "attacker CI exfiltration workflow",
                         str(workflow))
                    c2_found = True
                    break
            if "toJSON(secrets)" in content:
                emit("CRITICAL", "malicious-workflow-secret-exfil",
                     f"{wf_name} uses toJSON(secrets) -- exfiltrates ALL repo secrets to an artifact",
                     str(workflow))
                c2_found = True
            if not c2_found:
                emit("HIGH", "suspicious-workflow",
                     f"{wf_name} exists -- verify it is legitimate "
                     "(attacker injects this filename as CI exfil mechanism)",
                     str(workflow))
        except Exception:
            pass
    # Check for dependabout/ branches (typosquatted dependabot -- SAP wave)
    rc, out, _ = run(["git", "branch", "-a"])
    if rc == 0:
        for line in out.splitlines():
            if "dependabout/" in line:
                emit("CRITICAL", "dependabout-typosquat-branch",
                     f"Typosquatted 'dependabout/' branch: {line.strip()} -- "
                     "TeamPCP SAP wave uses this for CI token theft")


# CHECK 9: Git log attacker commits
def scan_git_attacker_commits() -> None:
    info(f"Scanning git log for attacker exfil commits ({ATTACKER_EXFIL_EMAIL}) ...")
    rc, out, _ = run(["git", "log", "--all", "--format=%H %ae %s"], timeout=30)
    if rc != 0 or not out.strip():
        return
    found = False
    for line in out.splitlines():
        if ATTACKER_EXFIL_EMAIL in line:
            emit("CRITICAL", "attacker-exfil-commit",
                 f"Commit by {ATTACKER_EXFIL_EMAIL} -- dead-drop may have run: {line.strip()}")
            found = True
        elif ATTACKER_COMMIT in line:
            emit("CRITICAL", "attacker-commit-ref",
                 f"Attacker commit {ATTACKER_COMMIT} in git log: {line.strip()}")
            found = True
        elif any(msg in line for msg in ATTACKER_EXFIL_MSGS):
            emit("HIGH", "suspicious-commit-message",
                 f"Suspicious commit message pattern: {line.strip()}")
    if not found:
        ok("No attacker exfil commits in git log")


# CHECK 10: Dune branches
def scan_dune_branches() -> None:
    info("Scanning git branches for Dune-themed worm propagation branches ...")
    rc, out, _ = run(["git", "branch", "-a"])
    if rc != 0 or not out.strip():
        return
    found = False
    for line in out.splitlines():
        branch = line.strip().lstrip("* ")
        if DUNE_BRANCH_PREFIX in branch and DUNE_PATTERN.search(branch):
            emit("CRITICAL", "dune-worm-branch",
                 f"Worm propagation branch: '{branch}' -- worm has self-propagated via this repo")
            found = True
        elif DUNE_PATTERN.search(branch):
            emit("HIGH", "dune-themed-branch",
                 f"Dune-themed branch '{branch}' -- verify not an attacker dead-drop")
    if not found:
        ok("No Dune-themed worm branches found")


# CHECK 11: npm tokens + RANSOM TOKEN
def scan_npm_tokens() -> None:
    info("Auditing npm tokens (checking for RANSOM TOKEN) ...")
    rc, raw_out, _ = run(["npm", "token", "list"])
    if rc == -1:
        info("npm not available -- skipping token audit")
        return
    if RANSOM_TOKEN_DESCRIPTION in (raw_out or ""):
        emit("CRITICAL", "ransom-token-detected",
             f"RANSOM TOKEN FOUND: description='{RANSOM_TOKEN_DESCRIPTION}'. "
             "The gh-token-monitor daemon polls api.github.com/user every 60 s. "
             "Receiving a 40x triggers 'rm -rf ~/'. "
             "ACTION: network-isolate machine -> forensic image -> revoke token "
             "from a separate admin account that is NOT on this machine.")

    rc2, json_out, _ = run(["npm", "token", "list", "--json"])
    if rc2 == 0 and json_out.strip():
        try:
            tokens = json.loads(json_out)
            if tokens:
                for t in tokens:
                    if RANSOM_TOKEN_DESCRIPTION in str(t.get("name", "")) or \
                       RANSOM_TOKEN_DESCRIPTION in str(t.get("description", "")):
                        emit("CRITICAL", "ransom-token-confirmed",
                             "Ransom token confirmed in JSON output.")
                emit("HIGH", "npm-tokens-present",
                     f"{len(tokens)} npm token(s) -- revoke unknowns AFTER machine isolation")
            else:
                ok("No npm tokens found")
        except Exception:
            pass


# CHECK 12: Shell history
def scan_shell_history() -> None:
    info("Scanning shell history for IOC indicators ...")
    history_files = [
        Path.home() / ".bash_history",
        Path.home() / ".zsh_history",
        Path.home() / ".sh_history",
    ]
    indicators = list(C2_DOMAINS) + list(C2_IPS) + list(PAYLOAD_FILENAMES) + [ATTACKER_COMMIT]
    for hf in history_files:
        if not hf.exists():
            continue
        try:
            content = hf.read_text(errors="replace")
            for ind in indicators:
                if ind in content:
                    emit("HIGH", "history-ioc",
                         f"IOC '{ind}' found in shell history", str(hf))
        except PermissionError:
            pass


# CHECK 13: CI environment
def scan_ci_env() -> None:
    info("Checking CI environment for credential leakage ...")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for var in [
            "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
            "GITHUB_TOKEN", "NPM_TOKEN", "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW", "RUNNER_OS",
        ]:
            if os.environ.get(var):
                emit("HIGH", "ci-credential-exposure",
                     f"${var} is set -- verify not exfiltrated during compromised-package run")
        rc, out, _ = run(["ps", "aux"])
        if rc == 0 and "python" in out and "/proc/" in out and "mem" in out:
            emit("CRITICAL", "ci-proc-mem-read",
                 "python3 /proc/*/mem access detected -- worm's GitHub Actions secret "
                 "extraction technique (extracts masked secrets from runner heap)")
    oidc_cache = Path.home() / ".cache/github-oidc"
    if oidc_cache.exists():
        emit("HIGH", "ci-oidc-cache",
             "GitHub OIDC token cache found -- may indicate stolen OIDC token",
             str(oidc_cache))


# CHECK 14: Git remotes
def scan_git_remotes() -> None:
    info("Checking git remotes for attacker/dead-drop indicators ...")
    rc, out, _ = run(["git", "remote", "-v"])
    if rc != 0 or not out.strip():
        return
    for line in out.splitlines():
        if DUNE_PATTERN.search(line):
            emit("HIGH", "dune-themed-remote",
                 f"Dune-themed git remote -- possible dead-drop: {line.strip()}")
    if "git-tanstack.com" in out:
        emit("CRITICAL", "c2-git-remote",
             "C2 domain git-tanstack.com found in git remotes")
    for acct in ATTACKER_GITHUB_ACCOUNTS:
        if acct in out:
            emit("CRITICAL", "attacker-github-remote",
                 f"Attacker GitHub account '{acct}' found in git remotes")


# SLSA provenance warning
def warn_slsa() -> None:
    emit("HIGH", "slsa-provenance-warning",
         "Mini Shai-Hulud is the first documented attack generating valid SLSA Build Level 3 "
         "provenance via GitHub Actions OIDC pipeline hijack (pull_request_target + cache poisoning). "
         "'npm audit signatures' passing does NOT prove safety. "
         "CVSS 9.6 Critical. Affected: 170+ npm packages, 2 PyPI packages, "
         "373-403 malicious versions, 518M+ cumulative downloads. "
         "Mitigations: restrict pull_request_target, scope OIDC audience, "
         "pin exact versions + verify SHA-256.")


# MAIN
def main() -> None:
    global use_json

    parser = argparse.ArgumentParser(description="CC-4781 / Mini Shai-Hulud scanner")
    parser.add_argument("--json",    action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--deep",    action="store_true", help="Recursively find all node_modules under CWD")
    parser.add_argument("--npm-dir", metavar="DIR",       help="Scan only this node_modules directory")
    args = parser.parse_args()
    use_json = args.json

    if not use_json:
        print(f"\n{BOLD}CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner{RESET}")
        print("NHS Cyber Alert CC-4781  |  CVE-2026-45321 (CVSS 9.6)  |  GHSA-g7cv-rxg3-hmpx")
        print(f"Host: {platform.node()}  OS: {platform.system()} {platform.release()}")
        total_versions = sum(len(v) for v in MALICIOUS_NPM_VERSIONS.values())
        print(f"Checking {len(MALICIOUS_NPM_VERSIONS)} npm packages "
              f"({total_versions} malicious versions), "
              f"{len(MALICIOUS_PYPI_VERSIONS)} PyPI packages\n")
        print(f"{RED}{BOLD}*** RANSOM TOKEN WARNING ***")
        print("If a ransom npm token is found, DO NOT REVOKE IT until the machine is")
        print("network-isolated. The gh-token-monitor daemon polls api.github.com/user")
        print(f"every 60 s and executes 'rm -rf ~/' if the token is revoked.{RESET}\n")

    scan_npm(args.npm_dir, args.deep)
    scan_lockfile()
    scan_pypi()
    scan_persistence()
    scan_payload_files()
    scan_c2_indicators()
    scan_c2_connections()
    scan_optdeps_injection()
    scan_prepare_script()
    scan_malicious_workflow()
    scan_git_attacker_commits()
    scan_dune_branches()
    scan_npm_tokens()
    scan_shell_history()
    scan_ci_env()
    scan_git_remotes()
    warn_slsa()

    if use_json:
        print(json.dumps({"host": platform.node(), "findings": findings}, indent=2))
    else:
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        high     = [f for f in findings if f["severity"] == "HIGH"]
        print()
        if critical:
            print(f"{RED}{BOLD}RESULT: {len(critical)} CRITICAL / {len(high)} HIGH{RESET}")
            print(f"{RED}ISOLATE machine from network FIRST, THEN rotate credentials.{RESET}")
            print(f"{RED}Do NOT revoke npm tokens before network isolation.{RESET}")
        elif high:
            print(f"{YELLOW}{BOLD}RESULT: 0 CRITICAL / {len(high)} HIGH{RESET}")
            print(f"{YELLOW}Review HIGH findings and remediate.{RESET}")
        else:
            print(f"{GREEN}{BOLD}RESULT: No CRITICAL or HIGH findings{RESET}")
            print(f"{GREEN}Continue monitoring for updated IOC lists.{RESET}")
        print()
        print("References:")
        print("  https://digital.nhs.uk/cyber-alerts/2026/cc-4781")
        print("  https://github.com/advisories/GHSA-g7cv-rxg3-hmpx")
        print("  https://nvd.nist.gov/vuln/detail/CVE-2026-45321")
        print("  https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem")
        print("  https://research.jfrog.com/post/shai-hulud-here-we-go-again/")
        print("  https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised")
        print("  Sigma rule 5299fadf-f228-4526-8274-251db1960be9 (Shai-Hulud Bun Execution)")
        print()
        print("Need help containing an active supply chain compromise?")
        print("Intrudify provides AI-powered pentesting and IR for npm/PyPI worm campaigns,")
        print("CI/CD pipeline hijacks, and GitHub Actions OIDC token abuse.")
        print("Contact: marc@intrudify.com  |  intrudify.com")
        print()


if __name__ == "__main__":
    main()
