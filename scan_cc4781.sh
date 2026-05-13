#!/usr/bin/env bash
# =============================================================================
# CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner (Shell)
# NHS Cyber Alert CC-4781  |  CVE-2026-45321  |  GHSA-g7cv-rxg3-hmpx
# TeamPCP threat group  |  Published 12 May 2026
#
# IOC sources (aggregated 2026-05-13):
#   GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity, Socket.dev,
#   Wiz Threat Research, Snyk, Aikido Security, Orca Security, Mend.io
#
# Usage:
#   chmod +x scan_cc4781.sh
#   ./scan_cc4781.sh [--json] [--deep] [--npm-dir /path/to/node_modules]
#
# Flags:
#   --json      Emit findings as newline-delimited JSON objects
#   --deep      Walk CWD recursively for node_modules (slow)
#   --npm-dir   Override node_modules location
#
# Checks performed:
#   1.  npm compromised versions (exact per-package, 170+ packages)
#   2.  PyPI compromised packages (guardrails-ai, mistralai, litellm, telnyx, lightning)
#   3.  Persistence implants (macOS LaunchAgent / Linux systemd, Claude Code hook,
#       VS Code folderOpen task)
#   4.  Payload artefacts + SHA-256 hash verification
#   5.  C2 domains in /etc/hosts and proxy env vars
#   6.  DNS resolution of C2 domains (11 tracked domains)
#   7.  Active connections to C2 IPs (5 tracked IPs)
#   8.  package.json optionalDependencies github: injection
#   9.  package.json prepare script injection (bun run tanstack_runner.js)
#  10.  Malicious .github/workflows (codeql_analysis.yml + format-check.yml)
#  11.  Git log -- attacker exfil commits (claude@users.noreply.github.com)
#  12.  Dune-themed worm propagation branches + dependabout/ typosquat
#  13.  npm token audit + RANSOM TOKEN detection (DO NOT REVOKE without isolating)
#  14.  Shell history IOC matches
#  15.  GitHub Actions credential exposure
#  16.  Dune-themed git remotes
#  17.  Secondary persistence: sysmon/pgmon disguise, litellm .pth, Kubernetes
#  18.  TeamPCP malware identification strings
#  19.  SLSA provenance bypass warning
#
# CRITICAL WARNINGS:
#   RANSOM TOKEN: npm token 'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner'
#   gh-token-monitor daemon polls api.github.com/user every 60 s.
#   A 40x response (token revoked) triggers: rm -rf ~/
#   SEQUENCE: network-isolate -> forensic image -> revoke from separate admin account.
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

JSON_MODE=0
DEEP=0
NPM_DIR_OVERRIDE=""
CRITICAL_COUNT=0
HIGH_COUNT=0

RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)    JSON_MODE=1 ;;
    --deep)    DEEP=1 ;;
    --npm-dir) NPM_DIR_OVERRIDE="$2"; shift ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
  shift
done

# IOC DATA
# Format: "package|v1 v2 v3 ..."  (space-separated exact malicious versions)
# Sources: GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity,
#          Socket.dev, Wiz, Snyk, Aikido, Orca, Mend.io (aggregated 2026-05-13)

NPM_MALICIOUS=(
  # @tanstack (42 packages -- exact confirmed versions, GHSA-g7cv-rxg3-hmpx)
  "@tanstack/arktype-adapter|1.166.12 1.166.15"
  "@tanstack/eslint-plugin-router|1.161.9 1.161.12"
  "@tanstack/eslint-plugin-start|0.0.4 0.0.7"
  "@tanstack/history|1.161.9 1.161.12"
  "@tanstack/nitro-v2-vite-plugin|1.154.12 1.154.15"
  "@tanstack/react-router|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.169.5 1.169.8"
  "@tanstack/react-router-devtools|1.166.16 1.166.19"
  "@tanstack/react-router-ssr-query|1.166.15 1.166.18"
  "@tanstack/react-start|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.167.68 1.167.71"
  "@tanstack/react-start-client|1.166.51 1.166.54"
  "@tanstack/react-start-rsc|0.0.47 0.0.50"
  "@tanstack/react-start-server|1.166.55 1.166.58"
  "@tanstack/router-cli|1.166.46 1.166.49"
  "@tanstack/router-core|1.169.5 1.169.8"
  "@tanstack/router-devtools|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.166.16 1.166.19"
  "@tanstack/router-devtools-core|1.167.6 1.167.9"
  "@tanstack/router-generator|1.166.45 1.166.48"
  "@tanstack/router-plugin|1.167.38 1.167.41"
  "@tanstack/router-ssr-query-core|1.168.3 1.168.6"
  "@tanstack/router-utils|1.161.11 1.161.14"
  "@tanstack/router-vite-plugin|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.166.53 1.166.56"
  "@tanstack/solid-router|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.169.5 1.169.8"
  "@tanstack/solid-router-devtools|1.166.16 1.166.19"
  "@tanstack/solid-router-ssr-query|1.166.15 1.166.18"
  "@tanstack/solid-start|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.167.65 1.167.68"
  "@tanstack/solid-start-client|1.166.50 1.166.53"
  "@tanstack/solid-start-server|1.166.54 1.166.57"
  "@tanstack/start|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921"
  "@tanstack/start-client-core|1.168.5 1.168.8"
  "@tanstack/start-fn-stubs|1.161.9 1.161.12"
  "@tanstack/start-plugin-core|1.169.23 1.169.26"
  "@tanstack/start-server-core|1.167.33 1.167.36"
  "@tanstack/start-static-server-functions|1.166.44 1.166.47"
  "@tanstack/start-storage-context|1.166.38 1.166.41"
  "@tanstack/valibot-adapter|1.166.12 1.166.15"
  "@tanstack/virtual-file-routes|1.161.10 1.161.13"
  "@tanstack/vue-router|0.0.1-insiders.20260511180920 0.0.1-insiders.20260511180921 1.169.5 1.169.8"
  "@tanstack/vue-router-devtools|1.166.16 1.166.19"
  "@tanstack/vue-router-ssr-query|1.166.15 1.166.18"
  "@tanstack/vue-start|1.167.61 1.167.64"
  "@tanstack/vue-start-client|1.166.46 1.166.49"
  "@tanstack/vue-start-server|1.166.50 1.166.53"
  "@tanstack/zod-adapter|1.166.12 1.166.15"
  # @uipath (66 packages -- source: JFrog Security Research)
  "@uipath/access-policy-sdk|0.3.1"
  "@uipath/access-policy-tool|0.3.1"
  "@uipath/admin-tool|0.1.1"
  "@uipath/agent-sdk|1.0.2"
  "@uipath/agent-tool|1.0.1"
  "@uipath/agent.sdk|0.0.18"
  "@uipath/agent-x|1.0.1"
  "@uipath/aops-policy-tool|0.3.1"
  "@uipath/ap-chat|1.5.7"
  "@uipath/api-workflow-tool|1.0.1"
  "@uipath/apollo-core|1.1.2 5.9.2"
  "@uipath/apollo-react|4.24.5"
  "@uipath/apollo-wind|2.16.2"
  "@uipath/auth|1.0.1"
  "@uipath/case-tool|1.0.1"
  "@uipath/cli|1.0.1 1.0.5"
  "@uipath/codedagent-tool|1.0.1"
  "@uipath/codedagents-tool|0.1.12"
  "@uipath/codedapp-tool|1.0.1"
  "@uipath/common|1.0.1"
  "@uipath/context-grounding-tool|0.1.1"
  "@uipath/data-fabric-tool|1.0.2"
  "@uipath/docsai-tool|1.0.1"
  "@uipath/filesystem|1.0.1"
  "@uipath/flow-tool|1.0.2"
  "@uipath/functions-tool|1.0.1"
  "@uipath/gov-tool|0.3.1"
  "@uipath/identity-tool|0.1.1"
  "@uipath/insights-sdk|1.0.1"
  "@uipath/insights-tool|1.0.1"
  "@uipath/integrationservice-sdk|1.0.2"
  "@uipath/integrationservice-tool|1.0.2"
  "@uipath/llmgw-tool|1.0.1"
  "@uipath/maestro-sdk|1.0.1"
  "@uipath/maestro-tool|1.0.1"
  "@uipath/orchestrator-tool|1.0.1"
  "@uipath/packager-tool-apiworkflow|0.0.19"
  "@uipath/packager-tool-bpmn|0.0.9"
  "@uipath/packager-tool-case|0.0.9"
  "@uipath/packager-tool-connector|0.0.19"
  "@uipath/packager-tool-flow|0.0.19"
  "@uipath/packager-tool-functions|0.1.1"
  "@uipath/packager-tool-webapp|1.0.6"
  "@uipath/packager-tool-workflowcompiler|0.0.16"
  "@uipath/packager-tool-workflowcompiler-browser|0.0.34"
  "@uipath/platform-tool|1.0.1"
  "@uipath/project-packager|1.1.16"
  "@uipath/resource-tool|1.0.1"
  "@uipath/resourcecatalog-tool|0.1.1"
  "@uipath/resources-tool|0.1.11"
  "@uipath/robot|0.11.2 1.3.4"
  "@uipath/rpa-legacy-tool|1.0.1"
  "@uipath/rpa-tool|0.9.5"
  "@uipath/solution-packager|0.0.35"
  "@uipath/solution-tool|1.0.1"
  "@uipath/solutionpackager-sdk|1.0.11"
  "@uipath/solutionpackager-tool-core|0.0.34"
  "@uipath/tasks-tool|1.0.1"
  "@uipath/telemetry|0.0.7"
  "@uipath/test-manager-tool|1.0.2"
  "@uipath/tool-workflowcompiler|0.0.12"
  "@uipath/traces-tool|1.0.1"
  "@uipath/ui-widgets-multi-file-upload|1.0.1"
  "@uipath/uipath-python-bridge|1.0.1"
  "@uipath/vertical-solutions-tool|1.0.1"
  "@uipath/vss|0.1.6"
  "@uipath/widget.sdk|1.2.3"
  # @mistralai
  "@mistralai/mistralai|1.4.3 1.4.4 1.5.0 2.2.2 2.2.3 2.2.4"
  "@mistralai/mistralai-azure|1.5.0 1.7.1 1.7.2 1.7.3"
  "@mistralai/mistralai-gcp|1.5.0 1.7.1 1.7.2 1.7.3"
  # @opensearch-project
  "@opensearch-project/opensearch|3.5.3 3.6.2 3.7.0 3.8.0"
  # @squawk
  "@squawk/mcp|0.9.5"
  "@squawk/weather|0.5.10"
  "@squawk/flightplan|0.5.6"
  # @draftlab / @draftauth
  "@draftlab/auth|0.24.1 0.24.2"
  "@draftlab/auth-router|0.5.1 0.5.2"
  "@draftlab/db|0.16.1 0.16.2"
  "@draftauth/client|0.2.1 0.2.2"
  "@draftauth/core|0.13.1 0.13.2"
  # @beproduct
  "@beproduct/nestjs-auth|0.1.2 0.1.3 0.1.4 0.1.5 0.1.6 0.1.7 0.1.8 0.1.9 0.1.10 0.1.11 0.1.12 0.1.13 0.1.14 0.1.15 0.1.16 0.1.17 0.1.18 0.1.19"
  # @ml-toolkit-ts
  "@ml-toolkit-ts/preprocessing|1.0.2 1.0.3"
  "@ml-toolkit-ts/xgboost|1.0.3 1.0.4"
  # @mesadev
  "@mesadev/rest|0.28.3"
  "@mesadev/saguaro|0.4.22"
  "@mesadev/sdk|0.28.3"
  # @dirigible-ai
  "@dirigible-ai/sdk|0.6.2 0.6.3"
  # @taskflow-corp
  "@taskflow-corp/cli|0.1.24 0.1.25 0.1.26 0.1.27 0.1.28 0.1.29"
  # @tolka
  "@tolka/cli|1.0.2 1.0.3 1.0.4 1.0.6"
  # @supersurkhet
  "@supersurkhet/cli|0.0.2 0.0.3 0.0.4 0.0.5 0.0.6 0.0.7"
  "@supersurkhet/sdk|0.0.2 0.0.3 0.0.4 0.0.5 0.0.6 0.0.7"
  # SAP @cap-js / mbt wave (April 29, 2026 -- malicious publisher: cloudmtabot)
  "@cap-js/db-service|2.10.1"
  "@cap-js/sqlite|2.2.2"
  "@cap-js/postgres|2.2.2"
  "mbt|1.2.48"
  # Unscoped packages
  "intercom-client|7.0.4"
  "lightning|2.6.2 2.6.3"
  "safe-action|0.8.3 0.8.4"
  "cmux-agent-mcp|0.1.3 0.1.4 0.1.5 0.1.6 0.1.7 0.1.8"
  "git-git-git|1.0.8 1.0.9 1.0.10 1.0.12"
  "git-branch-selector|1.3.3 1.3.4 1.3.5 1.3.7"
  "nextmove-mcp|0.1.3 0.1.4 0.1.5 0.1.7"
  "agentwork-cli|0.1.4 0.1.5"
  "ml-toolkit-ts|1.0.4 1.0.5"
  "wot-api|0.8.1 0.8.2 0.8.4"
  "cross-stitch|1.1.3 1.1.4 1.1.6"
  "ts-dna|3.0.1 3.0.2 3.0.4"
)

PYPI_MALICIOUS=(
  "guardrails-ai|0.10.1"
  "mistralai|2.4.6"
  "litellm|1.82.7 1.82.8"
  "telnyx|4.87.1 4.87.2"
  "lightning|2.6.2 2.6.3"
)

C2_DOMAINS=(
  "git-tanstack.com"
  "filev2.getsession.org"
  "api.masscan.cloud"
  "seed1.getsession.org"
  "seed2.getsession.org"
  "seed3.getsession.org"
  "scan.aquasecurtiy.org"
  "checkmarx.zone"
  "models.litellm.cloud"
  "recv.hackmoltrepeat.com"
  "nsa.cat"
)
C2_IPS=("83.142.209.194" "83.142.209.203" "45.148.10.212" "46.151.182.203" "23.142.184.129")

PAYLOAD_FILES=(
  "router_runtime.js"
  "router_init.js"
  "tanstack_runner.js"
  "bun_environment.js"
  "setup.mjs"
  "transformers.pyz"
  "gh-token-monitor"
  "execution.js"
  "litellm_init.pth"
  "kamikaze.sh"
  "hangup.wav"
  "ringtone.wav"
  "sysmon.py"
)

# Known-bad SHA-256 hashes: hash|description
KNOWN_BAD_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c|router_init.js -- stage-1 loader (2,341,681 bytes)"
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96|tanstack_runner.js -- worm engine (2,339,346 bytes, 3-layer obfuscated JS)"
  "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b|@tanstack/setup package.json -- attacker publish-stage manifest"
  "2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe27678b2df360bd90d3df|setup.mjs -- Bun loader / preinstall script (5,047 bytes)"
  "29c729852fce5a53e30a1541d9fec79c915b2e13f1eda94a5978cf0aae0d88d9|npm payload variant #1 (non-TanStack packages)"
  "d4a2086ea18f5e39cd867b8b06918a524eabb21d45ea98aad07357b98173458a|npm payload variant #2 (non-TanStack packages)"
  "2a314ea8be337e1ca9ec833ed13ed854d9fd38bce0a519cf288f3bec8d9e6f30|PyPI __init__.py -- Python ecosystem payload"
  "5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b|transformers.pyz -- PyPI zipapp payload"
  "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34|setup.mjs (SAP @cap-js wave)"
  "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7|embedded /proc/mem dumper (SAP wave)"
  "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a|entrypoint.sh -- Trivy action payload (204 lines)"
)

ATTACKER_COMMIT="79ac49eedf774dd4b0cfa308722bc463cfe5885c"
ATTACKER_EXFIL_EMAIL="claude@users.noreply.github.com"
ATTACKER_GITHUB_ACCOUNTS=("voicproducoes" "zblgg" "cloudmtabot" "MegaGame10418" "hackerbot-claw")
RANSOM_TOKEN_DESC="IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"
DUNE_REGEX="(shai.?hulud|here.we.go.again|lisan.al.gaib|muad.?dib|fremkit|sandworm|atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|laza|melange|mentat|navigator|ornithopter|phibian|powindah|prana|prescient|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|thumper|tleilaxu)"
DUNE_BRANCH_PREFIX="dependabot/github_actions/format/"

MACOS_LAUNCHAGENT="$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
LINUX_SYSTEMD_UNIT="$HOME/.config/systemd/user/gh-token-monitor.service"

SYSMON_PATHS=(
  "$HOME/.config/systemd/user/sysmon.service"
  "$HOME/.config/systemd/user/pgmon.service"
  "$HOME/.config/sysmon/sysmon.py"
  "$HOME/.local/share/pgmon/service.py"
  "/etc/systemd/system/sysmon.service"
)

MALWARE_STRINGS=(
  "svksjrhjkcejg"
  "OhNoWhatsGoingOnWithGitHub"
  "__DAEMONIZED"
  "TeamPCP Cloud stealer"
  "ctf-scramble-v2"
  "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"
  "EveryBoiWeBuildIsAWormyBoi"
  "Exiting as russian language detected"
)

# Output helpers
emit_finding() {
  local severity="$1" category="$2" detail="$3" path="${4:-}"
  if [[ $severity == "CRITICAL" ]]; then CRITICAL_COUNT=$((CRITICAL_COUNT+1)); else HIGH_COUNT=$((HIGH_COUNT+1)); fi
  if [[ $JSON_MODE -eq 1 ]]; then
    local p_field=""; [[ -n $path ]] && p_field=", \"path\": \"$(echo "$path" | sed 's/\\/\\\\/g; s/"/\\"/g')\""
    echo "{\"severity\": \"$severity\", \"category\": \"$category\", \"detail\": \"$(echo "$detail" | sed 's/"/\\"/g')\"$p_field}"
  else
    local colour="$YELLOW"; [[ $severity == "CRITICAL" ]] && colour="$RED"
    local loc=""; [[ -n $path ]] && loc="  -> $path"
    echo -e "${colour}${BOLD}[$severity]${RESET} ${BOLD}${category}${RESET}: $detail$loc"
  fi
}
info() { [[ $JSON_MODE -eq 0 ]] && echo -e "${CYAN}[INFO]${RESET} $1" || true; }
ok()   { [[ $JSON_MODE -eq 0 ]] && echo -e "${GREEN}[OK]${RESET}   $1" || true; }

# Helpers
extract_version() {
  local f="$1"
  if command -v python3 &>/dev/null; then
    python3 -c "import json,sys; d=json.load(open('$f')); print(d.get('version',''))" 2>/dev/null || true
  else
    grep -m1 '"version"' "$f" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' 2>/dev/null || true
  fi
}

sha256_of() {
  local f="$1"
  if command -v sha256sum &>/dev/null; then sha256sum "$f" | awk '{print $1}'
  elif command -v shasum &>/dev/null;   then shasum -a 256 "$f" | awk '{print $1}'
  else echo "unavailable"
  fi
}

check_npm_pkg() {
  local pkg="$1" bad_versions="$2" nm_dir="$3"
  local pkg_json="$nm_dir/$pkg/package.json"
  [[ -f "$pkg_json" ]] || return 0
  local ver; ver="$(extract_version "$pkg_json")"
  [[ -z "$ver" ]] && return 0
  for bv in $bad_versions; do
    if [[ "$ver" == "$bv" ]]; then
      emit_finding "CRITICAL" "npm-compromised-package" \
        "${pkg}@${ver} is a confirmed-malicious version" "$pkg_json"
    fi
  done
}

# Check 1: npm packages
scan_npm() {
  info "Scanning ${#NPM_MALICIOUS[@]} npm package IOCs for compromised versions ..."
  local nm_dirs=()

  if [[ -n "$NPM_DIR_OVERRIDE" ]]; then
    nm_dirs=("$NPM_DIR_OVERRIDE")
  else
    if command -v npm &>/dev/null; then
      local gnm; gnm="$(npm root -g 2>/dev/null)" && [[ -d "$gnm" ]] && nm_dirs+=("$gnm")
    fi
    [[ -d "$(pwd)/node_modules" ]] && nm_dirs+=("$(pwd)/node_modules")
    if [[ $DEEP -eq 1 ]]; then
      while IFS= read -r d; do nm_dirs+=("$d"); done \
        < <(find "$(pwd)" -name node_modules -type d 2>/dev/null)
    fi
  fi

  if [[ ${#nm_dirs[@]} -eq 0 ]]; then
    info "No node_modules found -- skipping npm scan"
    return
  fi

  for nm_dir in "${nm_dirs[@]}"; do
    for entry in "${NPM_MALICIOUS[@]}"; do
      check_npm_pkg "${entry%%|*}" "${entry##*|}" "$nm_dir"
    done
  done
}

# Check lockfiles
scan_lockfiles() {
  info "Scanning lockfiles for compromised package entries ..."
  for pat in "package-lock.json" "pnpm-lock.yaml" "yarn.lock"; do
    while IFS= read -r lf; do
      for entry in "${NPM_MALICIOUS[@]}"; do
        local pkg="${entry%%|*}" bad_vers="${entry##*|}"
        if grep -qF "\"$pkg\"" "$lf" 2>/dev/null; then
          for bv in $bad_vers; do
            grep -qF "$bv" "$lf" 2>/dev/null && \
              emit_finding "HIGH" "lockfile-bad-version" "${pkg}@${bv} referenced in lockfile" "$lf"
          done
        fi
      done
    done < <(find "$(pwd)" -name "$pat" -not -path "*/node_modules/*" 2>/dev/null)
  done
}

# Check 2: PyPI
scan_pypi() {
  info "Checking installed PyPI packages ..."
  local py; py="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
  [[ -z "$py" ]] && { info "Python not found -- skipping PyPI scan"; return; }
  for entry in "${PYPI_MALICIOUS[@]}"; do
    local dist="${entry%%|*}" bad_vers="${entry##*|}"
    local ver; ver="$($py -c "import importlib.metadata as m; print(m.version('$dist'))" 2>/dev/null || true)"
    [[ -z "$ver" ]] && continue
    for bv in $bad_vers; do
      [[ "$ver" == "$bv" ]] && \
        emit_finding "CRITICAL" "pypi-compromised-package" "${dist}==${ver} is a known-malicious version"
    done
  done
}

# Check 3: Persistence
scan_persistence() {
  info "Checking for gh-token-monitor persistence implant ..."
  local os_name; os_name="$(uname -s)"
  if [[ "$os_name" == "Darwin" ]]; then
    if [[ -f "$MACOS_LAUNCHAGENT" ]]; then
      emit_finding "CRITICAL" "persistence-daemon" \
        "macOS LaunchAgent found -- stop daemon BEFORE revoking npm tokens (ransom wipe triggers on revocation)" \
        "$MACOS_LAUNCHAGENT"
    else
      ok "macOS LaunchAgent not present"
    fi
  elif [[ "$os_name" == "Linux" ]]; then
    [[ -f "$LINUX_SYSTEMD_UNIT" ]] && \
      emit_finding "CRITICAL" "persistence-daemon" \
        "Linux systemd user unit found -- systemctl --user stop gh-token-monitor BEFORE revoking npm tokens" \
        "$LINUX_SYSTEMD_UNIT" || ok "Linux systemd user unit not present"
    [[ -f "/etc/systemd/system/gh-token-monitor.service" ]] && \
      emit_finding "CRITICAL" "persistence-daemon" \
        "System-wide systemd unit found" \
        "/etc/systemd/system/gh-token-monitor.service"
  fi

  # Claude Code SessionStart hook
  local claude_settings="$HOME/.claude/settings.json"
  if [[ -f "$claude_settings" ]] && command -v python3 &>/dev/null; then
    local hook_result
    hook_result="$(python3 -c "
import json, sys
try:
    d = json.load(open('$claude_settings'))
    hooks = d.get('hooks', {}).get('SessionStart', [])
    for h in hooks:
        cmd = str(h.get('command',''))
        if 'setup.mjs' in cmd or 'tanstack_runner' in cmd or 'router_runtime' in cmd:
            print('MALICIOUS:' + cmd)
except: pass
" 2>/dev/null || true)"
    if [[ -n "$hook_result" ]]; then
      emit_finding "CRITICAL" "persistence-claude-hook" \
        "Malicious Claude Code SessionStart hook: ${hook_result#MALICIOUS:}" "$claude_settings"
    fi
  fi

  # VS Code folderOpen task
  local vscode_tasks; vscode_tasks="$(pwd)/.vscode/tasks.json"
  if [[ -f "$vscode_tasks" ]]; then
    if grep -qE "setup\.mjs|tanstack_runner" "$vscode_tasks" 2>/dev/null; then
      emit_finding "CRITICAL" "persistence-vscode-task" \
        "Malicious VS Code folderOpen task found -- triggers on folder open" "$vscode_tasks"
    fi
  fi

  pgrep -x gh-token-monitor &>/dev/null && \
    emit_finding "CRITICAL" "persistence-process" \
      "gh-token-monitor process is currently running -- isolate before revoking tokens" || \
    ok "gh-token-monitor process not running"
}

# Check 4: Payload files + hash verification
scan_payload_files() {
  info "Searching for payload artefacts and verifying SHA-256 hashes ..."
  local search_dirs=("$HOME" "$(pwd)" "$HOME/.claude" "$HOME/.vscode" \
                     "$HOME/.cache/node" "$HOME/.npm/_npx" "$HOME/.pnpm-store" \
                     "$HOME/.config/gh-token-monitor")
  local find_args=()
  for fname in "${PAYLOAD_FILES[@]}"; do
    [[ ${#find_args[@]} -gt 0 ]] && find_args+=("-o")
    find_args+=("-name" "$fname")
  done
  local found=0
  declare -A seen_paths
  for sdir in "${search_dirs[@]}"; do
    [[ -d "$sdir" ]] || continue
    while IFS= read -r match; do
      [[ -f "$match" ]] || continue
      [[ -n "${seen_paths[$match]+isset}" ]] && continue
      seen_paths[$match]=1
      local fname; fname="$(basename "$match")"
      local digest; digest="$(sha256_of "$match")"
      local known_bad=0
      for hash_entry in "${KNOWN_BAD_HASHES[@]}"; do
        local khash="${hash_entry%%|*}" kdesc="${hash_entry##*|}"
        if [[ "$digest" == "$khash" ]]; then
          emit_finding "CRITICAL" "payload-confirmed-malicious" \
            "CONFIRMED MALICIOUS: $fname (sha256=$digest) -- $kdesc" "$match"
          known_bad=1; break
        fi
      done
      local fsize=0
      fsize="$(wc -c < "$match" 2>/dev/null || echo 0)"
      local size_warn=""
      [[ "$fsize" -gt 2000000 ]] && size_warn=" (SUSPICIOUS SIZE: ~2.3 MB worm engine)"
      [[ $known_bad -eq 0 ]] && \
        emit_finding "HIGH" "payload-artefact" \
          "Payload filename $fname found (sha256=$digest, size=${fsize} bytes)${size_warn}" \
          "$match"
      found=1
    done < <(find "$sdir" \( "${find_args[@]}" \) 2>/dev/null)
  done
  [[ $found -eq 0 ]] && ok "No payload artefact filenames found"
}

# Check 5: C2 in /etc/hosts and proxy env
scan_c2_indicators() {
  info "Checking for C2 domain indicators ..."
  for dom in "${C2_DOMAINS[@]}"; do
    [[ -f /etc/hosts ]] && grep -qF "$dom" /etc/hosts 2>/dev/null && \
      emit_finding "HIGH" "c2-in-hosts" "$dom present in /etc/hosts"
    for var in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
      local val="${!var:-}"
      [[ "$val" == *"$dom"* ]] && emit_finding "HIGH" "c2-in-proxy-env" "$dom in \$$var"
    done
  done
}

# Check 6: DNS resolution
is_private_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^127\. ]] && return 0
  [[ "$ip" =~ ^169\.254\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
  return 1
}

scan_c2_dns() {
  info "Testing DNS resolution of C2 domains ..."
  for dom in "${C2_DOMAINS[@]}"; do
    local ip=""
    if command -v dig &>/dev/null;       then ip="$(dig +short "$dom" 2>/dev/null | head -1)"
    elif command -v nslookup &>/dev/null; then ip="$(nslookup "$dom" 2>/dev/null | awk '/^Address: /{print $2}' | head -1)"
    elif command -v getent &>/dev/null;   then ip="$(getent hosts "$dom" 2>/dev/null | awk '{print $1}' | head -1)"
    fi
    if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
      emit_finding "HIGH" "c2-dns-resolves" "$dom resolves to $ip -- C2 reachable from this host"
    else
      ok "$dom does not resolve"
    fi
  done
}

# Check 7: Active connections
scan_c2_connections() {
  info "Checking for active connections to C2 IPs ..."
  for ip in "${C2_IPS[@]}"; do
    local found=0
    command -v ss      &>/dev/null && ss -tn 2>/dev/null      | grep -qF "$ip" && found=1
    command -v netstat &>/dev/null && netstat -tn 2>/dev/null  | grep -qF "$ip" && found=1
    [[ $found -eq 1 ]] && \
      emit_finding "CRITICAL" "active-c2-connection" "Active connection to C2 IP $ip detected"
  done
}

# Check 8: optionalDependencies github: injection
scan_optdeps_injection() {
  info "Scanning package.json files for attacker optionalDependencies injection ..."
  local found=0
  while IFS= read -r pj; do
    echo "$pj" | grep -q "node_modules" && continue
    if command -v python3 &>/dev/null; then
      local result
      result="$(python3 - "$pj" "$ATTACKER_COMMIT" 2>/dev/null <<'PYEOF'
import json, sys
pj, commit = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(pj))
    for dep, ref in (d.get("optionalDependencies") or {}).items():
        if isinstance(ref, str) and "github:tanstack/router" in ref:
            print(f"GITHUB_OPTDEP:{dep}:{ref}")
        if isinstance(ref, str) and commit in ref:
            print(f"ATTACKER_COMMIT:{dep}:{ref}")
except Exception:
    pass
PYEOF
)"
      while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        if [[ "$hit" == GITHUB_OPTDEP:* ]]; then
          emit_finding "CRITICAL" "optdeps-github-injection" \
            "optionalDependencies '${hit#GITHUB_OPTDEP:}' points to attacker GitHub ref" "$pj"
          found=1
        elif [[ "$hit" == ATTACKER_COMMIT:* ]]; then
          emit_finding "CRITICAL" "optdeps-attacker-commit" \
            "optionalDependencies '${hit#ATTACKER_COMMIT:}' contains attacker commit $ATTACKER_COMMIT" "$pj"
          found=1
        fi
      done <<< "$result"
    else
      if grep -qF "github:tanstack/router" "$pj" 2>/dev/null; then
        emit_finding "CRITICAL" "optdeps-github-injection" \
          "package.json contains 'github:tanstack/router' optionalDependency -- attacker injection pattern" "$pj"
        found=1
      fi
      if grep -qF "$ATTACKER_COMMIT" "$pj" 2>/dev/null; then
        emit_finding "CRITICAL" "optdeps-attacker-commit" \
          "package.json contains attacker commit $ATTACKER_COMMIT" "$pj"
        found=1
      fi
    fi
  done < <(find "$(pwd)" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null)
  [[ $found -eq 0 ]] && ok "No malicious optionalDependencies github: references found"
}

# Check 9: prepare script injection
scan_prepare_script() {
  info "Scanning package.json prepare scripts for malicious Bun invocation ..."
  local found=0
  while IFS= read -r pj; do
    echo "$pj" | grep -q "node_modules" && continue
    if command -v python3 &>/dev/null; then
      local prepare
      prepare="$(python3 -c "
import json, sys
try:
    d = json.load(open('$pj'))
    print((d.get('scripts') or {}).get('prepare',''))
except: pass
" 2>/dev/null || true)"
      if echo "$prepare" | grep -qiE "bun run tanstack_runner\.js"; then
        emit_finding "CRITICAL" "malicious-prepare-script" \
          "prepare script matches worm injection pattern: '$prepare'" "$pj"
        found=1
      fi
    else
      if grep -qE "bun run tanstack_runner\.js" "$pj" 2>/dev/null; then
        emit_finding "CRITICAL" "malicious-prepare-script" \
          "package.json prepare script contains 'bun run tanstack_runner.js' -- worm injection" "$pj"
        found=1
      fi
    fi
  done < <(find "$(pwd)" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null)
  [[ $found -eq 0 ]] && ok "No malicious prepare script patterns found"
}

# Check 10: Malicious workflow files
scan_malicious_workflow() {
  info "Checking for malicious .github/workflows files ..."
  local workflow_dir; workflow_dir="$(pwd)/.github/workflows"
  for wf_name in "codeql_analysis.yml" "format-check.yml"; do
    local workflow="$workflow_dir/$wf_name"
    [[ -f "$workflow" ]] || continue
    local c2_found=0
    for dom in "${C2_DOMAINS[@]}"; do
      if grep -qF "$dom" "$workflow" 2>/dev/null; then
        emit_finding "CRITICAL" "malicious-workflow" \
          "$wf_name contains C2 domain '$dom' -- attacker CI exfiltration workflow" "$workflow"
        c2_found=1; break
      fi
    done
    if grep -qF "toJSON(secrets)" "$workflow" 2>/dev/null; then
      emit_finding "CRITICAL" "malicious-workflow-secret-exfil" \
        "$wf_name uses toJSON(secrets) -- exfiltrates ALL repo secrets to an artifact" "$workflow"
      c2_found=1
    fi
    [[ $c2_found -eq 0 ]] && \
      emit_finding "HIGH" "suspicious-workflow" \
        "$wf_name exists -- verify it is legitimate (attacker injects this filename as CI exfil mechanism)" \
        "$workflow"
  done
  # Check for dependabout/ branches (typosquatted dependabot -- SAP wave)
  command -v git &>/dev/null || return
  local branches; branches="$(git branch -a 2>/dev/null)" || return
  while IFS= read -r line; do
    if echo "$line" | grep -qF "dependabout/"; then
      emit_finding "CRITICAL" "dependabout-typosquat-branch" \
        "Typosquatted 'dependabout/' branch: ${line## } -- TeamPCP SAP wave uses this for CI token theft"
    fi
  done <<< "$branches"
}

# Check 11: Git log for attacker exfil commits
scan_git_attacker_commits() {
  info "Scanning git log for attacker exfil commits ($ATTACKER_EXFIL_EMAIL) ..."
  command -v git &>/dev/null || return
  local log_out; log_out="$(git log --all --format="%H %ae %s" 2>/dev/null)" || return
  local found=0
  while IFS= read -r line; do
    if echo "$line" | grep -qF "$ATTACKER_EXFIL_EMAIL"; then
      emit_finding "CRITICAL" "attacker-exfil-commit" \
        "Commit authored by $ATTACKER_EXFIL_EMAIL -- dead-drop exfil may have run: $line"
      found=1
    elif echo "$line" | grep -qF "$ATTACKER_COMMIT"; then
      emit_finding "CRITICAL" "attacker-commit-ref" \
        "Attacker commit $ATTACKER_COMMIT referenced in git log: $line"
      found=1
    elif echo "$line" | grep -qF "EveryBoiWeBuildIsAWormyBoi"; then
      emit_finding "HIGH" "suspicious-commit-message" \
        "TeamPCP worm commit message found: $line"
      found=1
    fi
  done <<< "$log_out"
  [[ $found -eq 0 ]] && ok "No attacker exfil commits found in git log"
}

# Check 12: Dune-themed branches
scan_dune_branches() {
  info "Scanning git branches for Dune-themed worm propagation branches ..."
  command -v git &>/dev/null || return
  local branches; branches="$(git branch -a 2>/dev/null)" || return
  local found=0
  while IFS= read -r line; do
    local branch; branch="${line#\* }"; branch="${branch## }"
    if echo "$branch" | grep -qF "$DUNE_BRANCH_PREFIX" && echo "$branch" | grep -qiE "$DUNE_REGEX"; then
      emit_finding "CRITICAL" "dune-worm-branch" \
        "Dune-themed worm branch detected: '$branch' -- worm has self-propagated via this repo"
      found=1
    elif echo "$branch" | grep -qiE "$DUNE_REGEX"; then
      emit_finding "HIGH" "dune-themed-branch" \
        "Dune-themed branch '$branch' -- verify it is not an attacker dead-drop"
    fi
  done <<< "$branches"
  [[ $found -eq 0 ]] && ok "No Dune-themed worm propagation branches found"
}

# Check 13: npm tokens + RANSOM TOKEN
scan_npm_tokens() {
  info "Auditing npm tokens (checking for RANSOM TOKEN) ..."
  command -v npm &>/dev/null || { info "npm not available -- skipping token audit"; return; }
  local raw_out; raw_out="$(npm token list 2>/dev/null)" || { info "npm token list failed (not authenticated?)"; return; }
  if echo "$raw_out" | grep -qF "$RANSOM_TOKEN_DESC"; then
    emit_finding "CRITICAL" "ransom-token-detected" \
      "RANSOM TOKEN FOUND: '$RANSOM_TOKEN_DESC'. The gh-token-monitor daemon polls api.github.com/user every 60 s. A 40x triggers 'rm -rf ~/'. ACTION: network-isolate -> forensic image -> revoke from separate admin account."
  fi
  local json_out; json_out="$(npm token list --json 2>/dev/null)" || true
  local count=0
  if [[ -n "$json_out" ]] && command -v python3 &>/dev/null; then
    count="$(python3 -c "import json,sys; l=json.loads(sys.stdin.read()); print(len(l))" <<< "$json_out" 2>/dev/null || echo 0)"
  fi
  if [[ "$count" -gt 0 ]]; then
    emit_finding "HIGH" "npm-tokens-present" \
      "$count npm token(s) found -- review via 'npm token list' and revoke unknowns AFTER network isolation"
  else
    ok "No npm tokens found"
  fi
}

# Check 14: Shell history IOC scan
scan_shell_history() {
  info "Scanning shell history for IOC indicators ..."
  local history_files=("$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history")
  local indicators=("${C2_DOMAINS[@]}" "${C2_IPS[@]}" "${PAYLOAD_FILES[@]}" "$ATTACKER_COMMIT")
  for hf in "${history_files[@]}"; do
    [[ -f "$hf" ]] || continue
    for ind in "${indicators[@]}"; do
      grep -qF "$ind" "$hf" 2>/dev/null && \
        emit_finding "HIGH" "history-ioc" "IOC '$ind' found in shell history" "$hf"
    done
  done
}

# Check 15: CI credential exposure
scan_ci_env() {
  info "Checking CI environment ..."
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    for var in "ACTIONS_RUNTIME_TOKEN" "ACTIONS_ID_TOKEN_REQUEST_TOKEN" "ACTIONS_ID_TOKEN" \
               "ACTIONS_ID_TOKEN_REQUEST_URL" "GITHUB_TOKEN" "NPM_TOKEN" \
               "GITHUB_REPOSITORY" "GITHUB_WORKFLOW" "RUNNER_OS"; do
      [[ -n "${!var:-}" ]] && \
        emit_finding "HIGH" "ci-credential-exposure" \
          "\$$var is set -- verify not exfiltrated during compromised-package run"
    done
    if ps aux 2>/dev/null | grep -v grep | grep -q "python" && \
       ls /proc/*/fd 2>/dev/null | grep -q "mem"; then
      emit_finding "CRITICAL" "ci-proc-mem-read" \
        "python3 /proc/*/mem access detected -- matches worm's GitHub Actions secret extraction technique (extracts masked secrets from runner heap)"
    fi
  fi
  local oidc_cache="$HOME/.cache/github-oidc"
  [[ -d "$oidc_cache" ]] && emit_finding "HIGH" "ci-oidc-cache" \
    "GitHub OIDC token cache found -- may indicate stolen OIDC token" "$oidc_cache"
}

# Check 16: Git remotes
scan_git_remotes() {
  info "Checking git remotes for attacker/dead-drop indicators ..."
  command -v git &>/dev/null || return
  local remotes; remotes="$(git remote -v 2>/dev/null)" || return
  echo "$remotes" | grep -iE "$DUNE_REGEX" && \
    emit_finding "HIGH" "dune-themed-remote" "Dune-themed git remote detected -- possible dead-drop" || true
  echo "$remotes" | grep -qF "git-tanstack.com" && \
    emit_finding "CRITICAL" "c2-git-remote" "C2 domain git-tanstack.com in git remotes" || true
  for acct in "${ATTACKER_GITHUB_ACCOUNTS[@]}"; do
    echo "$remotes" | grep -qF "$acct" && \
      emit_finding "CRITICAL" "attacker-github-remote" \
        "Attacker GitHub account '$acct' found in git remotes" || true
  done
}

# Check 17: Advanced persistence
scan_advanced_persistence() {
  info "Checking for secondary persistence mechanisms (sysmon/pgmon/litellm/k8s) ..."
  # sysmon.service / pgmon.service disguise
  for sp in "${SYSMON_PATHS[@]}"; do
    [[ -f "$sp" ]] && emit_finding "CRITICAL" "persistence-sysmon-disguise" \
      "Persistence service disguised as system telemetry: $(basename "$sp") -- TeamPCP uses 'System Telemetry Service' label to blend in" \
      "$sp"
  done
  # litellm_init.pth -- Python startup hook (executes on any python invocation)
  local py; py="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
  if [[ -n "$py" ]]; then
    local site_pkgs
    site_pkgs="$($py -c "import site; print('\n'.join(site.getsitepackages()))" 2>/dev/null || true)"
    while IFS= read -r sp; do
      [[ -n "$sp" && -f "$sp/litellm_init.pth" ]] && \
        emit_finding "CRITICAL" "persistence-python-pth" \
          "litellm_init.pth found in Python site-packages -- executes malicious code on EVERY Python invocation" \
          "$sp/litellm_init.pth"
    done <<< "$site_pkgs"
  fi
  # WAV steganography containers
  while IFS= read -r match; do
    [[ -f "$match" ]] || continue
    local wf; wf="$(basename "$match")"
    emit_finding "HIGH" "wav-steganography" \
      "WAV steganography container $wf found -- TeamPCP embeds base64-encoded payloads in WAV files" \
      "$match"
  done < <(find "$HOME" "$(pwd)" \( -name "hangup.wav" -o -name "ringtone.wav" \) 2>/dev/null)
  # Kubernetes: check for malicious pods/DaemonSets
  if command -v kubectl &>/dev/null; then
    local k8s_pods
    k8s_pods="$(kubectl get pods -n kube-system --no-headers \
      -o custom-columns=NAME:.metadata.name 2>/dev/null || true)"
    while IFS= read -r pod; do
      [[ "$pod" == node-setup-* ]] && emit_finding "CRITICAL" "kubernetes-malicious-pod" \
        "TeamPCP Kubernetes pod found: '$pod' -- worm deploys DaemonSet in kube-system as 'node-setup-{node}'"
    done <<< "$k8s_pods"
    local k8s_ds
    k8s_ds="$(kubectl get daemonsets -n kube-system --no-headers \
      -o custom-columns=NAME:.metadata.name 2>/dev/null || true)"
    while IFS= read -r ds; do
      [[ "$ds" == host-provisioner* ]] && emit_finding "CRITICAL" "kubernetes-malicious-daemonset" \
        "TeamPCP DaemonSet found: '$ds' -- worm uses host-provisioner-* for Kubernetes persistence"
    done <<< "$k8s_ds"
  fi
}

# Check 18: TeamPCP malware identification strings
scan_malware_strings() {
  info "Scanning files for unique TeamPCP malware identification strings ..."
  local scan_dirs=("$HOME/.claude" "$HOME/.vscode" \
                   "$(pwd)/.github" "$(pwd)/.claude" "$(pwd)/.vscode")
  local found=0
  for sdir in "${scan_dirs[@]}"; do
    [[ -d "$sdir" ]] || continue
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      for sig in "${MALWARE_STRINGS[@]}"; do
        if grep -qF "$sig" "$f" 2>/dev/null; then
          emit_finding "CRITICAL" "malware-string-found" \
            "TeamPCP malware string '${sig:0:60}' found in file" "$f"
          found=1
        fi
      done
    done < <(find "$sdir" -type f -size -1M 2>/dev/null)
  done
  [[ $found -eq 0 ]] && ok "No TeamPCP malware identification strings found"
}

# SLSA warning
warn_slsa() {
  emit_finding "HIGH" "slsa-provenance-warning" \
    "Mini Shai-Hulud is the first documented attack producing valid SLSA Build Level 3 provenance via GitHub Actions OIDC pipeline hijack (pull_request_target + cache poisoning). 'npm audit signatures' passing does NOT prove safety. CVSS 9.6 Critical. Affected: 170+ npm packages, 5 PyPI packages, 373-403 malicious versions. Mitigations: restrict pull_request_target, scope OIDC audience, pin exact versions + verify SHA-256."
}

# Header
if [[ $JSON_MODE -eq 0 ]]; then
  echo ""
  echo -e "${BOLD}CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner (Shell)${RESET}"
  echo "NHS Cyber Alert CC-4781  |  CVE-2026-45321 (CVSS 9.6)  |  GHSA-g7cv-rxg3-hmpx"
  echo "Host: $(hostname)  OS: $(uname -sr)"
  echo "Checking ${#NPM_MALICIOUS[@]} npm packages, ${#PYPI_MALICIOUS[@]} PyPI packages"
  echo ""
  echo -e "${RED}${BOLD}*** RANSOM TOKEN WARNING ***${RESET}"
  echo -e "${RED}If a ransom npm token is found, DO NOT REVOKE IT until the machine is"
  echo -e "network-isolated. The gh-token-monitor daemon polls api.github.com/user"
  echo -e "every 60 s and executes 'rm -rf ~/' if the token is revoked.${RESET}"
  echo ""
fi

scan_npm
scan_lockfiles
scan_pypi
scan_persistence
scan_payload_files
scan_c2_indicators
scan_c2_dns
scan_c2_connections
scan_optdeps_injection
scan_prepare_script
scan_malicious_workflow
scan_git_attacker_commits
scan_dune_branches
scan_npm_tokens
scan_shell_history
scan_ci_env
scan_git_remotes
scan_advanced_persistence
scan_malware_strings
warn_slsa

if [[ $JSON_MODE -eq 0 ]]; then
  echo ""
  if [[ $CRITICAL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}RESULT: $CRITICAL_COUNT CRITICAL / $HIGH_COUNT HIGH findings${RESET}"
    echo -e "${RED}ISOLATE machine from network FIRST, THEN rotate credentials.${RESET}"
    echo -e "${RED}Do NOT revoke npm tokens before network isolation.${RESET}"
  elif [[ $HIGH_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}RESULT: 0 CRITICAL / $HIGH_COUNT HIGH findings${RESET}"
    echo -e "${YELLOW}Review HIGH findings and act on recommendations.${RESET}"
  else
    echo -e "${GREEN}${BOLD}RESULT: No CRITICAL or HIGH findings${RESET}"
    echo -e "${GREEN}Continue monitoring for updated IOC lists.${RESET}"
  fi
  echo ""
  echo "References:"
  echo "  https://digital.nhs.uk/cyber-alerts/2026/cc-4781"
  echo "  https://github.com/advisories/GHSA-g7cv-rxg3-hmpx"
  echo "  https://nvd.nist.gov/vuln/detail/CVE-2026-45321"
  echo "  https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
  echo "  https://research.jfrog.com/post/shai-hulud-here-we-go-again/"
  echo "  https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
  echo "  Sigma rule 5299fadf-f228-4526-8274-251db1960be9 (Shai-Hulud Malicious Bun Execution)"
  echo "  Palo Alto ATP signature 87120"
  echo ""
  echo "Need help containing an active supply chain compromise?"
  echo "Intrudify provides AI-powered pentesting and IR for npm/PyPI worm campaigns,"
  echo "CI/CD pipeline hijacks, and GitHub Actions OIDC token abuse."
  echo "Contact: marc@intrudify.com  |  intrudify.com"
  echo ""
fi
