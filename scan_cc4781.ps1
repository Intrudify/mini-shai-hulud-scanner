#Requires -Version 5.1
<#
.SYNOPSIS
    CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner (PowerShell)
.DESCRIPTION
    NHS Cyber Alert CC-4781  |  CVE-2026-45321  |  GHSA-g7cv-rxg3-hmpx
    TeamPCP threat group  |  Published 12 May 2026

    IOC sources (aggregated 2026-05-13):
      GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity, Socket.dev,
      Wiz Threat Research, Snyk, Aikido Security, Orca Security, Mend.io

    Checks:
      1.  npm compromised versions (exact per-package, 170+ packages)
      2.  PyPI compromised packages (guardrails-ai, mistralai, litellm, telnyx, lightning)
      3.  Persistence implants (Scheduled Task, HKCU Run key, AppData startup,
          Claude Code SessionStart hook, VS Code folderOpen task)
      4.  Payload artefacts + SHA-256 hash verification
      5.  C2 domains in hosts file, proxy settings, WinHTTP proxy
      6.  DNS resolution of C2 domains (11 tracked domains)
      7.  Active TCP connections to C2 IPs (5 tracked IPs)
      8.  package.json optionalDependencies github: injection
      9.  package.json prepare script injection (bun run tanstack_runner.js)
     10.  Malicious .github/workflows (codeql_analysis.yml + format-check.yml)
     11.  Git log - attacker exfil commits (claude@users.noreply.github.com)
     12.  Dune-themed worm propagation branches + dependabout/ typosquat
     13.  npm token audit + RANSOM TOKEN detection (DO NOT REVOKE without isolating)
     14.  PowerShell history IOC match
     15.  CI environment credential leakage
     16.  Dune-themed git remotes + attacker GitHub accounts
     17.  Secondary persistence: sysmon/pgmon disguise, litellm .pth, Kubernetes
     18.  TeamPCP malware identification strings
     19.  SLSA provenance bypass warning

    *** RANSOM TOKEN WARNING ***
    If a ransom npm token is found, DO NOT REVOKE IT before network-isolating the machine.
    The gh-token-monitor daemon polls api.github.com/user every 60 s.
    A 40x response (token revoked) triggers 'rm -rf ~/'.
    Sequence: network-isolate -> forensic image -> revoke token from separate admin account.

.PARAMETER Json
    Output machine-readable JSON instead of coloured text.
.PARAMETER Deep
    Recursively find all node_modules directories under CWD.
.PARAMETER NpmDir
    Scan only this specific node_modules directory.
.EXAMPLE
    .\scan_cc4781.ps1
    .\scan_cc4781.ps1 -Json
    .\scan_cc4781.ps1 -Deep
    .\scan_cc4781.ps1 -NpmDir C:\projects\myapp\node_modules
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$Deep,
    [string]$NpmDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- IOC DATA -----------------------------------------------------------------
# Sources: GHSA-g7cv-rxg3-hmpx, JFrog Security Research, StepSecurity,
#          Socket.dev, Wiz, Snyk, Aikido, Orca, Mend.io (aggregated 2026-05-13)

$MaliciousNpm = @{
    # -- @tanstack (42 packages -- exact confirmed versions, GHSA-g7cv-rxg3-hmpx) --
    '@tanstack/arktype-adapter'              = @('1.166.12','1.166.15')
    '@tanstack/eslint-plugin-router'         = @('1.161.9','1.161.12')
    '@tanstack/eslint-plugin-start'          = @('0.0.4','0.0.7')
    '@tanstack/history'                      = @('1.161.9','1.161.12')
    '@tanstack/nitro-v2-vite-plugin'         = @('1.154.12','1.154.15')
    '@tanstack/react-router'                 = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.169.5','1.169.8')
    '@tanstack/react-router-devtools'        = @('1.166.16','1.166.19')
    '@tanstack/react-router-ssr-query'       = @('1.166.15','1.166.18')
    '@tanstack/react-start'                  = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.167.68','1.167.71')
    '@tanstack/react-start-client'           = @('1.166.51','1.166.54')
    '@tanstack/react-start-rsc'              = @('0.0.47','0.0.50')
    '@tanstack/react-start-server'           = @('1.166.55','1.166.58')
    '@tanstack/router-cli'                   = @('1.166.46','1.166.49')
    '@tanstack/router-core'                  = @('1.169.5','1.169.8')
    '@tanstack/router-devtools'              = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.166.16','1.166.19')
    '@tanstack/router-devtools-core'         = @('1.167.6','1.167.9')
    '@tanstack/router-generator'             = @('1.166.45','1.166.48')
    '@tanstack/router-plugin'                = @('1.167.38','1.167.41')
    '@tanstack/router-ssr-query-core'        = @('1.168.3','1.168.6')
    '@tanstack/router-utils'                 = @('1.161.11','1.161.14')
    '@tanstack/router-vite-plugin'           = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.166.53','1.166.56')
    '@tanstack/solid-router'                 = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.169.5','1.169.8')
    '@tanstack/solid-router-devtools'        = @('1.166.16','1.166.19')
    '@tanstack/solid-router-ssr-query'       = @('1.166.15','1.166.18')
    '@tanstack/solid-start'                  = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.167.65','1.167.68')
    '@tanstack/solid-start-client'           = @('1.166.50','1.166.53')
    '@tanstack/solid-start-server'           = @('1.166.54','1.166.57')
    '@tanstack/start'                        = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921')
    '@tanstack/start-client-core'            = @('1.168.5','1.168.8')
    '@tanstack/start-fn-stubs'               = @('1.161.9','1.161.12')
    '@tanstack/start-plugin-core'            = @('1.169.23','1.169.26')
    '@tanstack/start-server-core'            = @('1.167.33','1.167.36')
    '@tanstack/start-static-server-functions'= @('1.166.44','1.166.47')
    '@tanstack/start-storage-context'        = @('1.166.38','1.166.41')
    '@tanstack/valibot-adapter'              = @('1.166.12','1.166.15')
    '@tanstack/virtual-file-routes'          = @('1.161.10','1.161.13')
    '@tanstack/vue-router'                   = @('0.0.1-insiders.20260511180920','0.0.1-insiders.20260511180921','1.169.5','1.169.8')
    '@tanstack/vue-router-devtools'          = @('1.166.16','1.166.19')
    '@tanstack/vue-router-ssr-query'         = @('1.166.15','1.166.18')
    '@tanstack/vue-start'                    = @('1.167.61','1.167.64')
    '@tanstack/vue-start-client'             = @('1.166.46','1.166.49')
    '@tanstack/vue-start-server'             = @('1.166.50','1.166.53')
    '@tanstack/zod-adapter'                  = @('1.166.12','1.166.15')
    # -- @uipath (66 packages -- source: JFrog Security Research) -------------
    '@uipath/access-policy-sdk'              = @('0.3.1')
    '@uipath/access-policy-tool'             = @('0.3.1')
    '@uipath/admin-tool'                     = @('0.1.1')
    '@uipath/agent-sdk'                      = @('1.0.2')
    '@uipath/agent-tool'                     = @('1.0.1')
    '@uipath/agent.sdk'                      = @('0.0.18')
    '@uipath/agent-x'                        = @('1.0.1')
    '@uipath/aops-policy-tool'               = @('0.3.1')
    '@uipath/ap-chat'                        = @('1.5.7')
    '@uipath/api-workflow-tool'              = @('1.0.1')
    '@uipath/apollo-core'                    = @('1.1.2','5.9.2')
    '@uipath/apollo-react'                   = @('4.24.5')
    '@uipath/apollo-wind'                    = @('2.16.2')
    '@uipath/auth'                           = @('1.0.1')
    '@uipath/case-tool'                      = @('1.0.1')
    '@uipath/cli'                            = @('1.0.1','1.0.5')
    '@uipath/codedagent-tool'                = @('1.0.1')
    '@uipath/codedagents-tool'               = @('0.1.12')
    '@uipath/codedapp-tool'                  = @('1.0.1')
    '@uipath/common'                         = @('1.0.1')
    '@uipath/context-grounding-tool'         = @('0.1.1')
    '@uipath/data-fabric-tool'               = @('1.0.2')
    '@uipath/docsai-tool'                    = @('1.0.1')
    '@uipath/filesystem'                     = @('1.0.1')
    '@uipath/flow-tool'                      = @('1.0.2')
    '@uipath/functions-tool'                 = @('1.0.1')
    '@uipath/gov-tool'                       = @('0.3.1')
    '@uipath/identity-tool'                  = @('0.1.1')
    '@uipath/insights-sdk'                   = @('1.0.1')
    '@uipath/insights-tool'                  = @('1.0.1')
    '@uipath/integrationservice-sdk'         = @('1.0.2')
    '@uipath/integrationservice-tool'        = @('1.0.2')
    '@uipath/llmgw-tool'                     = @('1.0.1')
    '@uipath/maestro-sdk'                    = @('1.0.1')
    '@uipath/maestro-tool'                   = @('1.0.1')
    '@uipath/orchestrator-tool'              = @('1.0.1')
    '@uipath/packager-tool-apiworkflow'      = @('0.0.19')
    '@uipath/packager-tool-bpmn'             = @('0.0.9')
    '@uipath/packager-tool-case'             = @('0.0.9')
    '@uipath/packager-tool-connector'        = @('0.0.19')
    '@uipath/packager-tool-flow'             = @('0.0.19')
    '@uipath/packager-tool-functions'        = @('0.1.1')
    '@uipath/packager-tool-webapp'           = @('1.0.6')
    '@uipath/packager-tool-workflowcompiler' = @('0.0.16')
    '@uipath/packager-tool-workflowcompiler-browser' = @('0.0.34')
    '@uipath/platform-tool'                  = @('1.0.1')
    '@uipath/project-packager'               = @('1.1.16')
    '@uipath/resource-tool'                  = @('1.0.1')
    '@uipath/resourcecatalog-tool'           = @('0.1.1')
    '@uipath/resources-tool'                 = @('0.1.11')
    '@uipath/robot'                          = @('0.11.2','1.3.4')
    '@uipath/rpa-legacy-tool'                = @('1.0.1')
    '@uipath/rpa-tool'                       = @('0.9.5')
    '@uipath/solution-packager'              = @('0.0.35')
    '@uipath/solution-tool'                  = @('1.0.1')
    '@uipath/solutionpackager-sdk'           = @('1.0.11')
    '@uipath/solutionpackager-tool-core'     = @('0.0.34')
    '@uipath/tasks-tool'                     = @('1.0.1')
    '@uipath/telemetry'                      = @('0.0.7')
    '@uipath/test-manager-tool'              = @('1.0.2')
    '@uipath/tool-workflowcompiler'          = @('0.0.12')
    '@uipath/traces-tool'                    = @('1.0.1')
    '@uipath/ui-widgets-multi-file-upload'   = @('1.0.1')
    '@uipath/uipath-python-bridge'           = @('1.0.1')
    '@uipath/vertical-solutions-tool'        = @('1.0.1')
    '@uipath/vss'                            = @('0.1.6')
    '@uipath/widget.sdk'                     = @('1.2.3')
    # -- @mistralai ------------------------------------------------------------
    '@mistralai/mistralai'                   = @('1.4.3','1.4.4','1.5.0','2.2.2','2.2.3','2.2.4')
    '@mistralai/mistralai-azure'             = @('1.5.0','1.7.1','1.7.2','1.7.3')
    '@mistralai/mistralai-gcp'               = @('1.5.0','1.7.1','1.7.2','1.7.3')
    # -- @opensearch-project ---------------------------------------------------
    '@opensearch-project/opensearch'         = @('3.5.3','3.6.2','3.7.0','3.8.0')
    # -- @squawk ---------------------------------------------------------------
    '@squawk/mcp'                            = @('0.9.5')
    '@squawk/weather'                        = @('0.5.10')
    '@squawk/flightplan'                     = @('0.5.6')
    # -- @draftlab / @draftauth ------------------------------------------------
    '@draftlab/auth'                         = @('0.24.1','0.24.2')
    '@draftlab/auth-router'                  = @('0.5.1','0.5.2')
    '@draftlab/db'                           = @('0.16.1','0.16.2')
    '@draftauth/client'                      = @('0.2.1','0.2.2')
    '@draftauth/core'                        = @('0.13.1','0.13.2')
    # -- @beproduct ------------------------------------------------------------
    '@beproduct/nestjs-auth'                 = @('0.1.2','0.1.3','0.1.4','0.1.5','0.1.6','0.1.7','0.1.8','0.1.9','0.1.10','0.1.11','0.1.12','0.1.13','0.1.14','0.1.15','0.1.16','0.1.17','0.1.18','0.1.19')
    # -- @ml-toolkit-ts --------------------------------------------------------
    '@ml-toolkit-ts/preprocessing'           = @('1.0.2','1.0.3')
    '@ml-toolkit-ts/xgboost'                 = @('1.0.3','1.0.4')
    # -- @mesadev --------------------------------------------------------------
    '@mesadev/rest'                          = @('0.28.3')
    '@mesadev/saguaro'                       = @('0.4.22')
    '@mesadev/sdk'                           = @('0.28.3')
    # -- @dirigible-ai ---------------------------------------------------------
    '@dirigible-ai/sdk'                      = @('0.6.2','0.6.3')
    # -- @taskflow-corp --------------------------------------------------------
    '@taskflow-corp/cli'                     = @('0.1.24','0.1.25','0.1.26','0.1.27','0.1.28','0.1.29')
    # -- @tolka ----------------------------------------------------------------
    '@tolka/cli'                             = @('1.0.2','1.0.3','1.0.4','1.0.6')
    # -- @supersurkhet ---------------------------------------------------------
    '@supersurkhet/cli'                      = @('0.0.2','0.0.3','0.0.4','0.0.5','0.0.6','0.0.7')
    '@supersurkhet/sdk'                      = @('0.0.2','0.0.3','0.0.4','0.0.5','0.0.6','0.0.7')
    # -- SAP @cap-js / mbt wave (April 29, 2026 -- malicious publisher: cloudmtabot) --
    '@cap-js/db-service'                     = @('2.10.1')
    '@cap-js/sqlite'                         = @('2.2.2')
    '@cap-js/postgres'                       = @('2.2.2')
    'mbt'                                    = @('1.2.48')
    # -- Unscoped packages -----------------------------------------------------
    'intercom-client'                        = @('7.0.4')
    'lightning'                              = @('2.6.2','2.6.3')
    'safe-action'                            = @('0.8.3','0.8.4')
    'cmux-agent-mcp'                         = @('0.1.3','0.1.4','0.1.5','0.1.6','0.1.7','0.1.8')
    'git-git-git'                            = @('1.0.8','1.0.9','1.0.10','1.0.12')
    'git-branch-selector'                    = @('1.3.3','1.3.4','1.3.5','1.3.7')
    'nextmove-mcp'                           = @('0.1.3','0.1.4','0.1.5','0.1.7')
    'agentwork-cli'                          = @('0.1.4','0.1.5')
    'ml-toolkit-ts'                          = @('1.0.4','1.0.5')
    'wot-api'                                = @('0.8.1','0.8.2','0.8.4')
    'cross-stitch'                           = @('1.1.3','1.1.4','1.1.6')
    'ts-dna'                                 = @('3.0.1','3.0.2','3.0.4')
}

$MaliciousPypi = @{
    'guardrails-ai' = @('0.10.1')
    'mistralai'     = @('2.4.6')
    'litellm'       = @('1.82.7','1.82.8')
    'telnyx'        = @('4.87.1','4.87.2')
    'lightning'     = @('2.6.2','2.6.3')
}

$C2Domains = @(
    'git-tanstack.com',
    'filev2.getsession.org',
    'api.masscan.cloud',
    'seed1.getsession.org',
    'seed2.getsession.org',
    'seed3.getsession.org',
    'scan.aquasecurtiy.org',
    'checkmarx.zone',
    'models.litellm.cloud',
    'recv.hackmoltrepeat.com',
    'nsa.cat'
)
$C2IPs = @('83.142.209.194','83.142.209.203','45.148.10.212','46.151.182.203','23.142.184.129')

$PayloadFiles = @(
    'router_runtime.js',
    'router_init.js',
    'tanstack_runner.js',
    'bun_environment.js',
    'setup.mjs',
    'transformers.pyz',
    'gh-token-monitor',
    'execution.js',
    'litellm_init.pth',
    'kamikaze.sh',
    'hangup.wav',
    'ringtone.wav',
    'sysmon.py'
)

$KnownBadSha256 = @{
    'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c' = 'router_init.js -- stage-1 loader (2,341,681 bytes)'
    '2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96' = 'tanstack_runner.js -- worm engine (2,339,346 bytes, 3-layer obfuscated JS)'
    '7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b' = '@tanstack/setup package.json -- attacker publish-stage manifest'
    '2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe27678b2df360bd90d3df' = 'setup.mjs -- Bun loader / preinstall script (5,047 bytes)'
    '29c729852fce5a53e30a1541d9fec79c915b2e13f1eda94a5978cf0aae0d88d9' = 'npm payload variant #1 (non-TanStack packages)'
    'd4a2086ea18f5e39cd867b8b06918a524eabb21d45ea98aad07357b98173458a' = 'npm payload variant #2 (non-TanStack packages)'
    '2a314ea8be337e1ca9ec833ed13ed854d9fd38bce0a519cf288f3bec8d9e6f30' = 'PyPI __init__.py -- Python ecosystem payload'
    '5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b' = 'transformers.pyz -- PyPI zipapp payload'
    '4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34' = 'setup.mjs (SAP @cap-js wave, identical across all 4 SAP packages)'
    '29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7' = 'embedded /proc/mem dumper (SAP wave -- extracts runner secrets from memory)'
    '18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a' = 'entrypoint.sh -- Trivy action payload (204 lines, 17,592 bytes)'
}

$AttackerCommit     = '79ac49eedf774dd4b0cfa308722bc463cfe5885c'
$AttackerExfilEmail = 'claude@users.noreply.github.com'
$AttackerGitHubAccounts = @('voicproducoes','zblgg','cloudmtabot','MegaGame10418','hackerbot-claw')
$RansomTokenDesc    = 'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner'
$DunePattern        = 'shai.?hulud|here.we.go.again|lisan.al.gaib|muad.?dib|fremkit|sandworm|atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|melange|mentat|navigator|ornithopter|sardaukar|sayyadina|sietch|siridar|stillsuit|thumper|tleilaxu'
$DuneBranchPrefix   = 'dependabot/github_actions/format/'

$MalwareStrings = @(
    'svksjrhjkcejg',
    'OhNoWhatsGoingOnWithGitHub',
    '__DAEMONIZED',
    'TeamPCP Cloud stealer',
    'ctf-scramble-v2',
    'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner',
    'EveryBoiWeBuildIsAWormyBoi',
    'Exiting as russian language detected'
)

$StartupDir = [Environment]::GetFolderPath('Startup')
$RegRunPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# --- OUTPUT HELPERS -----------------------------------------------------------
$Script:Findings      = [System.Collections.Generic.List[hashtable]]::new()
$Script:CriticalCount = 0
$Script:HighCount     = 0

function Emit-Finding {
    param(
        [ValidateSet('CRITICAL','HIGH')][string]$Severity,
        [string]$Category,
        [string]$Detail,
        [string]$Path = ''
    )
    $record = @{ severity=$Severity; category=$Category; detail=$Detail }
    if ($Path) { $record['path'] = $Path }
    $Script:Findings.Add($record)
    if ($Severity -eq 'CRITICAL') { $Script:CriticalCount++ } else { $Script:HighCount++ }
    if (-not $Json) {
        $colour = if ($Severity -eq 'CRITICAL') { 'Red' } else { 'Yellow' }
        $loc = if ($Path) { "  -> $Path" } else { '' }
        Write-Host "[$Severity] $Category`: $Detail$loc" -ForegroundColor $colour
    }
}
function Write-Info { if (-not $Json) { Write-Host "[INFO]  $args" -ForegroundColor Cyan  } }
function Write-Ok   { if (-not $Json) { Write-Host "[OK]    $args" -ForegroundColor Green } }

# --- CHECK 1: npm packages ----------------------------------------------------
function Get-NpmDirs {
    $dirs = [System.Collections.Generic.List[string]]::new()
    if ($NpmDir -and (Test-Path $NpmDir)) { $dirs.Add($NpmDir); return $dirs }
    $gnm = & npm root -g 2>$null
    if ($gnm -and (Test-Path $gnm)) { $dirs.Add($gnm) }
    $local = Join-Path (Get-Location) 'node_modules'
    if (Test-Path $local) { $dirs.Add($local) }
    if ($Deep) {
        Get-ChildItem -Path (Get-Location) -Recurse -Directory -Filter 'node_modules' -ErrorAction SilentlyContinue |
            Where-Object { $dirs -notcontains $_.FullName } |
            ForEach-Object { $dirs.Add($_.FullName) }
    }
    return $dirs
}

function Test-NpmPackage {
    param([string]$PkgName, [string[]]$BadVersions, [string]$NmDir)
    $parts = $PkgName -split '/'
    $pkgPath = $NmDir
    foreach ($part in $parts) { $pkgPath = Join-Path $pkgPath $part }
    $pkgJsonPath = Join-Path $pkgPath 'package.json'
    if (-not (Test-Path $pkgJsonPath)) { return }
    try {
        $ver = (Get-Content $pkgJsonPath -Raw | ConvertFrom-Json).version
        if ($ver -and $BadVersions -contains $ver) {
            Emit-Finding -Severity CRITICAL -Category 'npm-compromised-package' `
                -Detail "$PkgName@$ver is a confirmed-malicious version" -Path $pkgJsonPath
        }
    } catch { }
}

function Invoke-NpmScan {
    Write-Info "Scanning $($MaliciousNpm.Count) npm package IOCs for compromised versions ..."
    $nmDirs = Get-NpmDirs
    if ($nmDirs.Count -eq 0) { Write-Info "No node_modules found -- skipping npm scan"; return }
    foreach ($nmDir in $nmDirs) {
        foreach ($pkg in $MaliciousNpm.Keys) {
            Test-NpmPackage -PkgName $pkg -BadVersions $MaliciousNpm[$pkg] -NmDir $nmDir
        }
    }
}

function Invoke-LockfileScan {
    Write-Info "Scanning lockfiles for compromised package entries ..."
    foreach ($pat in @('package-lock.json','pnpm-lock.yaml','yarn.lock')) {
        $files = Get-ChildItem -Path (Get-Location) -Recurse -Filter $pat -ErrorAction SilentlyContinue
        foreach ($lf in $files) {
            $content = Get-Content $lf.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            foreach ($pkg in $MaliciousNpm.Keys) {
                if ($content -like "*`"$pkg`"*") {
                    foreach ($bv in $MaliciousNpm[$pkg]) {
                        if ($content -like "*$bv*") {
                            Emit-Finding -Severity HIGH -Category 'lockfile-bad-version' `
                                -Detail "$pkg@$bv referenced in lockfile" -Path $lf.FullName
                        }
                    }
                }
            }
        }
    }
}

# --- CHECK 2: PyPI ------------------------------------------------------------
function Invoke-PypiScan {
    Write-Info "Checking installed PyPI packages ..."
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $py) { Write-Info "Python not found -- skipping PyPI scan"; return }
    foreach ($dist in $MaliciousPypi.Keys) {
        $ver = & $py.Source -c "import importlib.metadata as m; print(m.version('$dist'))" 2>$null
        if ($ver) {
            foreach ($bv in $MaliciousPypi[$dist]) {
                if ($ver.Trim() -eq $bv) {
                    Emit-Finding -Severity CRITICAL -Category 'pypi-compromised-package' `
                        -Detail "$dist==$ver is a known-malicious version"
                }
            }
        }
    }
}

# --- CHECK 3: Persistence -----------------------------------------------------
function Invoke-PersistenceScan {
    Write-Info "Checking for gh-token-monitor persistence ..."
    $task = Get-ScheduledTask -TaskName 'gh-token-monitor' -ErrorAction SilentlyContinue
    if ($task) {
        Emit-Finding -Severity CRITICAL -Category 'persistence-scheduled-task' `
            -Detail "Scheduled Task 'gh-token-monitor' found -- stop BEFORE revoking npm tokens (ransom wipe risk)"
    } else { Write-Ok "No gh-token-monitor scheduled task" }

    if (Test-Path $RegRunPath) {
        $runVal = Get-ItemProperty -Path $RegRunPath -Name 'gh-token-monitor' -ErrorAction SilentlyContinue
        if ($runVal) {
            Emit-Finding -Severity CRITICAL -Category 'persistence-registry-run' `
                -Detail "HKCU Run key 'gh-token-monitor' found: $($runVal.'gh-token-monitor')" `
                -Path $RegRunPath
        } else { Write-Ok "No gh-token-monitor in HKCU Run" }
    }

    foreach ($fname in $PayloadFiles) {
        $p = Join-Path $StartupDir $fname
        if (Test-Path $p) {
            Emit-Finding -Severity CRITICAL -Category 'persistence-startup-folder' `
                -Detail "Payload file in Startup folder: $fname" -Path $p
        }
    }

    # Claude Code SessionStart hook
    $claudeSettings = Join-Path $env:USERPROFILE '.claude\settings.json'
    if (Test-Path $claudeSettings) {
        try {
            $data = Get-Content $claudeSettings -Raw | ConvertFrom-Json
            $hooks = $data.hooks.SessionStart
            if ($hooks) {
                foreach ($hook in $hooks) {
                    $cmd = [string]$hook.command
                    if ($cmd -like '*setup.mjs*' -or $cmd -like '*tanstack_runner*' -or $cmd -like '*router_runtime*') {
                        Emit-Finding -Severity CRITICAL -Category 'persistence-claude-hook' `
                            -Detail "Malicious Claude Code SessionStart hook: $cmd" -Path $claudeSettings
                    }
                }
            }
        } catch { }
    }

    # VS Code folderOpen task
    $vscodeTasks = Join-Path (Get-Location) '.vscode\tasks.json'
    if (Test-Path $vscodeTasks) {
        $content = Get-Content $vscodeTasks -Raw -ErrorAction SilentlyContinue
        if ($content -like '*setup.mjs*' -or $content -like '*tanstack_runner*') {
            Emit-Finding -Severity CRITICAL -Category 'persistence-vscode-task' `
                -Detail "Malicious VS Code folderOpen task found -- triggers on folder open" -Path $vscodeTasks
        }
    }

    $proc = Get-Process -Name 'gh-token-monitor' -ErrorAction SilentlyContinue
    if ($proc) {
        Emit-Finding -Severity CRITICAL -Category 'persistence-process' `
            -Detail "gh-token-monitor process is running (PID $($proc.Id)) -- isolate before revoking tokens"
    } else { Write-Ok "gh-token-monitor process not running" }
}

# --- CHECK 4: Payload files + hash verification --------------------------------
function Invoke-PayloadFileScan {
    Write-Info "Searching for payload artefacts and verifying SHA-256 hashes ..."
    $searchRoots = @(
        $env:USERPROFILE,
        (Get-Location).Path,
        (Join-Path $env:APPDATA 'npm'),
        (Join-Path $env:LOCALAPPDATA 'pnpm'),
        (Join-Path $env:APPDATA 'Code\User\globalStorage'),
        (Join-Path $env:USERPROFILE '.claude'),
        (Join-Path $env:USERPROFILE '.vscode'),
        (Join-Path $env:USERPROFILE '.config\gh-token-monitor')
    ) | Where-Object { $_ -and (Test-Path $_) }

    $found = $false
    foreach ($root in $searchRoots) {
        foreach ($fname in $PayloadFiles) {
            $hits = Get-ChildItem -Path $root -Recurse -Filter $fname -ErrorAction SilentlyContinue
            foreach ($m in $hits) {
                $digest = (Get-FileHash -Path $m.FullName -Algorithm SHA256).Hash.ToLower()
                if ($KnownBadSha256.ContainsKey($digest)) {
                    Emit-Finding -Severity CRITICAL -Category 'payload-confirmed-malicious' `
                        -Detail "CONFIRMED MALICIOUS: $fname (sha256=$digest) -- $($KnownBadSha256[$digest])" `
                        -Path $m.FullName
                } else {
                    $sizeWarn = if ($m.Length -gt 2000000) { ' (SUSPICIOUS SIZE: ~2.3 MB worm engine)' } else { '' }
                    Emit-Finding -Severity HIGH -Category 'payload-artefact' `
                        -Detail "Payload filename $fname (sha256=$digest, size=$($m.Length) bytes)$sizeWarn" `
                        -Path $m.FullName
                }
                $found = $true
            }
        }
    }
    if (-not $found) { Write-Ok "No payload artefact filenames found" }
}

# --- CHECK 5: C2 indicators ---------------------------------------------------
function Invoke-C2IndicatorScan {
    Write-Info "Checking for C2 domain indicators ..."
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        $hostsContent = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
        foreach ($dom in $C2Domains) {
            if ($hostsContent -like "*$dom*") {
                Emit-Finding -Severity HIGH -Category 'c2-in-hosts' -Detail "$dom present in hosts file" -Path $hostsPath
            }
        }
    }
    foreach ($var in @('http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')) {
        $val = [System.Environment]::GetEnvironmentVariable($var)
        if ($val) {
            foreach ($dom in $C2Domains) {
                if ($val -like "*$dom*") {
                    Emit-Finding -Severity HIGH -Category 'c2-in-proxy-env' -Detail "$dom in %$var%"
                }
            }
        }
    }
    try {
        $wpx = netsh winhttp show proxy 2>$null | Out-String
        foreach ($dom in $C2Domains) {
            if ($wpx -like "*$dom*") {
                Emit-Finding -Severity HIGH -Category 'c2-in-winhttp-proxy' -Detail "$dom in WinHTTP proxy"
            }
        }
    } catch { }
}

function Invoke-DnsScan {
    Write-Info "Testing DNS resolution of C2 domains ..."
    foreach ($dom in $C2Domains) {
        try {
            $result = Resolve-DnsName -Name $dom -Type A -ErrorAction Stop
            $ip = ($result | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1).IPAddress
            if ($ip) {
                Emit-Finding -Severity HIGH -Category 'c2-dns-resolves' `
                    -Detail "$dom resolves to $ip -- C2 reachable from this host"
            }
        } catch { Write-Ok "$dom does not resolve" }
    }
}

function Invoke-ConnectionScan {
    Write-Info "Checking for active connections to C2 IPs ..."
    foreach ($ip in $C2IPs) {
        $conns = Get-NetTCPConnection -RemoteAddress $ip -ErrorAction SilentlyContinue
        if ($conns) {
            foreach ($c in $conns) {
                Emit-Finding -Severity CRITICAL -Category 'active-c2-connection' `
                    -Detail "Active TCP connection to C2 $ip`:$($c.RemotePort) (State=$($c.State), PID=$($c.OwningProcess))"
            }
        }
    }
}

# --- CHECK 8: optionalDependencies injection -----------------------------------
function Invoke-OptdepsInjectionScan {
    Write-Info "Scanning package.json files for attacker optionalDependencies injection ..."
    $found = $false
    $pkgJsonFiles = Get-ChildItem -Path (Get-Location) -Recurse -Filter 'package.json' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*\node_modules\*' }
    foreach ($pj in $pkgJsonFiles) {
        try {
            $data = Get-Content $pj.FullName -Raw | ConvertFrom-Json
            $optDeps = $data.optionalDependencies
            if ($optDeps) {
                $optDeps.PSObject.Properties | ForEach-Object {
                    $dep = $_.Name; $ref = $_.Value
                    if ($ref -like '*github:tanstack/router*') {
                        Emit-Finding -Severity CRITICAL -Category 'optdeps-github-injection' `
                            -Detail "optionalDependencies['$dep'] = '$ref' -- attacker injection pattern" `
                            -Path $pj.FullName
                        $found = $true
                    }
                    if ($ref -like "*$AttackerCommit*") {
                        Emit-Finding -Severity CRITICAL -Category 'optdeps-attacker-commit' `
                            -Detail "optionalDependencies['$dep'] contains attacker commit $AttackerCommit" `
                            -Path $pj.FullName
                        $found = $true
                    }
                }
            }
        } catch { }
    }
    if (-not $found) { Write-Ok "No malicious optionalDependencies github: references found" }
}

# --- CHECK 9: prepare script injection ----------------------------------------
function Invoke-PrepareScriptScan {
    Write-Info "Scanning package.json prepare scripts for malicious Bun invocation ..."
    $found = $false
    $pkgJsonFiles = Get-ChildItem -Path (Get-Location) -Recurse -Filter 'package.json' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*\node_modules\*' }
    foreach ($pj in $pkgJsonFiles) {
        try {
            $data = Get-Content $pj.FullName -Raw | ConvertFrom-Json
            $prepare = $data.scripts.prepare
            if ($prepare -and $prepare -match 'bun run tanstack_runner\.js') {
                Emit-Finding -Severity CRITICAL -Category 'malicious-prepare-script' `
                    -Detail "prepare script matches worm injection pattern: '$prepare'" -Path $pj.FullName
                $found = $true
            }
        } catch { }
    }
    if (-not $found) { Write-Ok "No malicious prepare script patterns found" }
}

# --- CHECK 10: Malicious workflow files ---------------------------------------
function Invoke-MaliciousWorkflowScan {
    Write-Info "Checking for malicious .github/workflows files ..."
    $workflowDir = Join-Path (Get-Location) '.github\workflows'
    foreach ($wfName in @('codeql_analysis.yml','format-check.yml')) {
        $workflow = Join-Path $workflowDir $wfName
        if (-not (Test-Path $workflow)) { continue }
        $content = Get-Content $workflow -Raw -ErrorAction SilentlyContinue
        $c2Found = $false
        foreach ($dom in $C2Domains) {
            if ($content -like "*$dom*") {
                Emit-Finding -Severity CRITICAL -Category 'malicious-workflow' `
                    -Detail "$wfName contains C2 domain '$dom' -- attacker CI exfiltration workflow" `
                    -Path $workflow
                $c2Found = $true; break
            }
        }
        if ($content -like '*toJSON(secrets)*') {
            Emit-Finding -Severity CRITICAL -Category 'malicious-workflow-secret-exfil' `
                -Detail "$wfName uses toJSON(secrets) -- exfiltrates ALL repo secrets to an artifact" `
                -Path $workflow
            $c2Found = $true
        }
        if (-not $c2Found) {
            Emit-Finding -Severity HIGH -Category 'suspicious-workflow' `
                -Detail "$wfName exists -- verify it is legitimate (attacker injects this filename as CI exfil mechanism)" `
                -Path $workflow
        }
    }
    # Check for dependabout/ branches (typosquatted dependabot -- SAP wave)
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) { return }
    try {
        $branches = & git branch -a 2>$null
        foreach ($line in ($branches -split "`n")) {
            if ($line -like '*dependabout/*') {
                Emit-Finding -Severity CRITICAL -Category 'dependabout-typosquat-branch' `
                    -Detail "Typosquatted 'dependabout/' branch: $($line.Trim()) -- TeamPCP SAP wave uses this for CI token theft"
            }
        }
    } catch { }
}

# --- CHECK 11: Git log attacker commits ---------------------------------------
function Invoke-GitAttackerCommitScan {
    Write-Info "Scanning git log for attacker exfil commits ($AttackerExfilEmail) ..."
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) { Write-Info "git not found -- skipping"; return }
    try {
        $logOut = & git log --all --format="%H %ae %s" 2>$null
        $found = $false
        foreach ($line in ($logOut -split "`n")) {
            if ($line -like "*$AttackerExfilEmail*") {
                Emit-Finding -Severity CRITICAL -Category 'attacker-exfil-commit' `
                    -Detail "Commit authored by $AttackerExfilEmail -- dead-drop exfil may have run: $line"
                $found = $true
            } elseif ($line -like "*$AttackerCommit*") {
                Emit-Finding -Severity CRITICAL -Category 'attacker-commit-ref' `
                    -Detail "Attacker commit $AttackerCommit referenced in git log: $line"
                $found = $true
            } elseif ($line -like '*EveryBoiWeBuildIsAWormyBoi*') {
                Emit-Finding -Severity HIGH -Category 'suspicious-commit-message' `
                    -Detail "TeamPCP worm commit message found: $line"
                $found = $true
            }
        }
        if (-not $found) { Write-Ok "No attacker exfil commits in git log" }
    } catch { }
}

# --- CHECK 12: Dune-themed branches -------------------------------------------
function Invoke-DuneBranchScan {
    Write-Info "Scanning git branches for Dune-themed worm propagation branches ..."
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) { return }
    try {
        $branches = & git branch -a 2>$null
        $found = $false
        foreach ($line in ($branches -split "`n")) {
            $branch = $line.Trim().TrimStart('* ')
            if ($branch -match $DunePattern) {
                if ($branch -like "*$DuneBranchPrefix*") {
                    Emit-Finding -Severity CRITICAL -Category 'dune-worm-branch' `
                        -Detail "Dune-themed worm branch: '$branch' -- worm has self-propagated via this repo"
                } else {
                    Emit-Finding -Severity HIGH -Category 'dune-themed-branch' `
                        -Detail "Dune-themed branch '$branch' -- verify not an attacker dead-drop"
                }
                $found = $true
            }
        }
        if (-not $found) { Write-Ok "No Dune-themed worm propagation branches found" }
    } catch { }
}

# --- CHECK 13: npm token audit + RANSOM TOKEN ---------------------------------
function Invoke-NpmTokenScan {
    Write-Info "Auditing npm tokens (checking for RANSOM TOKEN) ..."
    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npmCmd) { Write-Info "npm not available -- skipping"; return }
    try {
        $rawOut = & npm token list 2>$null | Out-String
        if ($rawOut -like "*$RansomTokenDesc*") {
            Emit-Finding -Severity CRITICAL -Category 'ransom-token-detected' `
                -Detail "RANSOM TOKEN FOUND: '$RansomTokenDesc'. The gh-token-monitor daemon polls api.github.com/user every 60 s. A 40x triggers machine wipe. ACTION: network-isolate -> forensic image -> revoke from separate admin account."
        }
        $tokenJson = & npm token list --json 2>$null
        if ($tokenJson) {
            $tokens = $tokenJson | ConvertFrom-Json
            if ($tokens.Count -gt 0) {
                Emit-Finding -Severity HIGH -Category 'npm-tokens-present' `
                    -Detail "$($tokens.Count) npm token(s) found -- review and revoke unknowns AFTER machine isolation"
            } else { Write-Ok "No npm tokens found" }
        }
    } catch { Write-Info "npm token list failed (not authenticated?)" }
}

# --- CHECK 14: PowerShell history ---------------------------------------------
function Invoke-HistoryScan {
    Write-Info "Scanning PowerShell history for IOC indicators ..."
    $historyPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
    if (-not $historyPath) {
        $historyPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    }
    if (Test-Path $historyPath) {
        $content = Get-Content $historyPath -Raw -ErrorAction SilentlyContinue
        $indicators = $C2Domains + $C2IPs + $PayloadFiles + @($AttackerCommit)
        foreach ($ind in $indicators) {
            if ($content -like "*$ind*") {
                Emit-Finding -Severity HIGH -Category 'history-ioc' `
                    -Detail "IOC '$ind' found in PowerShell history" -Path $historyPath
            }
        }
    }
}

# --- CHECK 15: CI env credential exposure -------------------------------------
function Invoke-CiEnvScan {
    Write-Info "Checking CI environment ..."
    if ($env:GITHUB_ACTIONS -eq 'true') {
        foreach ($var in @('ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN',
                           'ACTIONS_ID_TOKEN','ACTIONS_ID_TOKEN_REQUEST_URL',
                           'GITHUB_TOKEN','NPM_TOKEN','GITHUB_REPOSITORY',
                           'GITHUB_WORKFLOW','RUNNER_OS')) {
            if ([System.Environment]::GetEnvironmentVariable($var)) {
                Emit-Finding -Severity HIGH -Category 'ci-credential-exposure' `
                    -Detail "%$var% is set -- verify not exfiltrated during compromised-package run"
            }
        }
    }
    $oidcCache = Join-Path $env:USERPROFILE '.cache\github-oidc'
    if (Test-Path $oidcCache) {
        Emit-Finding -Severity HIGH -Category 'ci-oidc-cache' `
            -Detail "GitHub OIDC token cache found -- may indicate stolen OIDC token" -Path $oidcCache
    }
}

# --- CHECK 16: Git remotes ----------------------------------------------------
function Invoke-GitRemoteScan {
    Write-Info "Checking git remotes for attacker/dead-drop indicators ..."
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) { return }
    try {
        $remotes = & git remote -v 2>$null | Out-String
        if ($remotes -match $DunePattern) {
            Emit-Finding -Severity HIGH -Category 'dune-themed-remote' `
                -Detail "Dune-themed git remote detected -- possible dead-drop"
        }
        if ($remotes -like '*git-tanstack.com*') {
            Emit-Finding -Severity CRITICAL -Category 'c2-git-remote' `
                -Detail "C2 domain git-tanstack.com in git remotes"
        }
        foreach ($acct in $AttackerGitHubAccounts) {
            if ($remotes -like "*$acct*") {
                Emit-Finding -Severity CRITICAL -Category 'attacker-github-remote' `
                    -Detail "Attacker GitHub account '$acct' found in git remotes"
            }
        }
    } catch { }
}

# --- CHECK 17: Advanced persistence ------------------------------------------
function Invoke-AdvancedPersistenceScan {
    Write-Info "Checking for secondary persistence mechanisms (sysmon/pgmon/litellm/k8s) ..."

    # sysmon.service / pgmon.service Windows equivalents
    foreach ($svcName in @('sysmon','pgmon')) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $svcPath = (Get-WmiObject -Class Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).PathName
            Emit-Finding -Severity HIGH -Category 'persistence-sysmon-disguise' `
                -Detail "Service '$svcName' found -- TeamPCP uses this name to disguise persistence (verify legitimacy). Path: $svcPath"
        }
    }

    # litellm_init.pth -- Python startup hook
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    if ($py) {
        try {
            $sitePkgs = & $py.Source -c "import site; print('\n'.join(site.getsitepackages()))" 2>$null
            foreach ($sp in ($sitePkgs -split "`n")) {
                $sp = $sp.Trim()
                if ($sp -and (Test-Path (Join-Path $sp 'litellm_init.pth'))) {
                    Emit-Finding -Severity CRITICAL -Category 'persistence-python-pth' `
                        -Detail "litellm_init.pth found in Python site-packages -- executes malicious code on EVERY Python invocation" `
                        -Path (Join-Path $sp 'litellm_init.pth')
                }
            }
        } catch { }
    }

    # WAV steganography containers
    foreach ($wf in @('hangup.wav','ringtone.wav')) {
        $hits = Get-ChildItem -Path $env:USERPROFILE -Recurse -Filter $wf -ErrorAction SilentlyContinue
        foreach ($h in $hits) {
            Emit-Finding -Severity HIGH -Category 'wav-steganography' `
                -Detail "WAV steganography container $wf found -- TeamPCP embeds base64-encoded payloads in WAV files" `
                -Path $h.FullName
        }
    }

    # Kubernetes: check for malicious pods/DaemonSets
    $kubectlCmd = Get-Command kubectl -ErrorAction SilentlyContinue
    if ($kubectlCmd) {
        try {
            $k8sPods = & kubectl get pods -n kube-system --no-headers `
                -o custom-columns=NAME:.metadata.name 2>$null
            foreach ($pod in ($k8sPods -split "`n")) {
                $pod = $pod.Trim()
                if ($pod -like 'node-setup-*') {
                    Emit-Finding -Severity CRITICAL -Category 'kubernetes-malicious-pod' `
                        -Detail "TeamPCP Kubernetes pod found: '$pod' -- worm deploys DaemonSet in kube-system"
                }
            }
            $k8sDs = & kubectl get daemonsets -n kube-system --no-headers `
                -o custom-columns=NAME:.metadata.name 2>$null
            foreach ($ds in ($k8sDs -split "`n")) {
                $ds = $ds.Trim()
                if ($ds -like 'host-provisioner*') {
                    Emit-Finding -Severity CRITICAL -Category 'kubernetes-malicious-daemonset' `
                        -Detail "TeamPCP DaemonSet found: '$ds' -- worm uses host-provisioner-* for Kubernetes persistence"
                }
            }
        } catch { }
    }
}

# --- CHECK 18: TeamPCP malware identification strings -------------------------
function Invoke-MalwareStringScan {
    Write-Info "Scanning files for unique TeamPCP malware identification strings ..."
    $scanDirs = @(
        (Join-Path $env:USERPROFILE '.claude'),
        (Join-Path $env:USERPROFILE '.vscode'),
        (Join-Path (Get-Location) '.github'),
        (Join-Path (Get-Location) '.claude'),
        (Join-Path (Get-Location) '.vscode')
    ) | Where-Object { Test-Path $_ }

    $found = $false
    foreach ($sdir in $scanDirs) {
        $files = Get-ChildItem -Path $sdir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -notin @('.png','.jpg','.gif','.ico') }
        foreach ($f in $files) {
            try {
                $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
                if (-not $content) { continue }
                foreach ($sig in $MalwareStrings) {
                    if ($content -like "*$sig*") {
                        Emit-Finding -Severity CRITICAL -Category 'malware-string-found' `
                            -Detail "TeamPCP malware string '$($sig.Substring(0,[Math]::Min(60,$sig.Length)))' found in file" `
                            -Path $f.FullName
                        $found = $true
                    }
                }
            } catch { }
        }
    }
    if (-not $found) { Write-Ok "No TeamPCP malware identification strings found" }
}

# --- SLSA warning -------------------------------------------------------------
function Write-SlsaWarning {
    Emit-Finding -Severity HIGH -Category 'slsa-provenance-warning' `
        -Detail "Mini Shai-Hulud is the first documented attack producing valid SLSA Build Level 3 provenance via GitHub Actions OIDC pipeline hijack (pull_request_target + cache poisoning). 'npm audit signatures' passing does NOT prove safety. CVSS 9.6 Critical. Affected: 170+ npm packages, 5 PyPI packages, 373-403 malicious versions. Mitigations: restrict pull_request_target, scope OIDC audience, pin exact versions + verify SHA-256. Sigma rule 5299fadf-f228-4526-8274-251db1960be9. Palo Alto ATP signature 87120."
}

# --- MAIN ---------------------------------------------------------------------
if (-not $Json) {
    Write-Host ""
    Write-Host "CC-4781 / Mini Shai-Hulud Supply-Chain Attack Scanner (PowerShell)" -ForegroundColor White
    Write-Host "NHS Cyber Alert CC-4781  |  CVE-2026-45321 (CVSS 9.6)  |  GHSA-g7cv-rxg3-hmpx"
    Write-Host "Host: $env:COMPUTERNAME  OS: $([System.Environment]::OSVersion.VersionString)"
    Write-Host "Checking $($MaliciousNpm.Count) npm package IOCs, $($MaliciousPypi.Count) PyPI packages"
    Write-Host ""
    Write-Host "*** RANSOM TOKEN WARNING ***" -ForegroundColor Red
    Write-Host "If a ransom npm token is found, DO NOT REVOKE IT before network-isolating the machine." -ForegroundColor Red
    Write-Host "The gh-token-monitor daemon polls api.github.com/user every 60 s." -ForegroundColor Red
    Write-Host "A 40x response triggers machine wipe. Isolate -> forensic image -> revoke from separate admin account." -ForegroundColor Red
    Write-Host ""
}

Invoke-NpmScan
Invoke-LockfileScan
Invoke-PypiScan
Invoke-PersistenceScan
Invoke-PayloadFileScan
Invoke-C2IndicatorScan
Invoke-DnsScan
Invoke-ConnectionScan
Invoke-OptdepsInjectionScan
Invoke-PrepareScriptScan
Invoke-MaliciousWorkflowScan
Invoke-GitAttackerCommitScan
Invoke-DuneBranchScan
Invoke-NpmTokenScan
Invoke-HistoryScan
Invoke-CiEnvScan
Invoke-GitRemoteScan
Invoke-AdvancedPersistenceScan
Invoke-MalwareStringScan
Write-SlsaWarning

if ($Json) {
    @{ host = $env:COMPUTERNAME; findings = $Script:Findings } | ConvertTo-Json -Depth 5
} else {
    Write-Host ""
    if ($Script:CriticalCount -gt 0) {
        Write-Host "RESULT: $($Script:CriticalCount) CRITICAL / $($Script:HighCount) HIGH findings" -ForegroundColor Red
        Write-Host "ISOLATE machine from network FIRST, THEN rotate credentials." -ForegroundColor Red
        Write-Host "Do NOT revoke npm tokens before network isolation (ransom wipe risk)." -ForegroundColor Red
    } elseif ($Script:HighCount -gt 0) {
        Write-Host "RESULT: 0 CRITICAL / $($Script:HighCount) HIGH findings" -ForegroundColor Yellow
        Write-Host "Review HIGH findings and act on recommendations." -ForegroundColor Yellow
    } else {
        Write-Host "RESULT: No CRITICAL or HIGH findings" -ForegroundColor Green
        Write-Host "Continue monitoring for updated IOC lists." -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "References:"
    Write-Host "  https://digital.nhs.uk/cyber-alerts/2026/cc-4781"
    Write-Host "  https://github.com/advisories/GHSA-g7cv-rxg3-hmpx"
    Write-Host "  https://nvd.nist.gov/vuln/detail/CVE-2026-45321"
    Write-Host "  https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    Write-Host "  https://research.jfrog.com/post/shai-hulud-here-we-go-again/"
    Write-Host "  https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
    Write-Host "  Sigma rule 5299fadf-f228-4526-8274-251db1960be9 (Shai-Hulud Malicious Bun Execution)"
    Write-Host "  Palo Alto ATP signature 87120"
    Write-Host ""
    Write-Host "Need help containing an active supply chain compromise?"
    Write-Host "Intrudify provides AI-powered pentesting and IR for npm/PyPI worm campaigns,"
    Write-Host "CI/CD pipeline hijacks, and GitHub Actions OIDC token abuse."
    Write-Host "Contact: marc@intrudify.com  |  intrudify.com"
    Write-Host ""
}
