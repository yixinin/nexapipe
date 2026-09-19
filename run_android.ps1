#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot Android debug loop for nexapipe: build the Rust cdylib, drop it into
    ui-android, install the debug APK, launch the app and capture logcat.

.DESCRIPTION
    Replaces the old cmd-style script (which called a build_android.bat that no
    longer exists) with the same flow plus preflight checks. Steps:

      1. Preflight  - locate cargo-ndk, adb, the SDK and the NDK; verify a device
                      is usable. Fails here instead of three minutes into a build.
      2. Rust build - cargo-ndk builds crates/nexapipe-client for aarch64-linux-android
                      with the features the app needs, then the .so is copied to
                      ui-android/app/src/main/jniLibs/arm64-v8a/. The file must stay
                      named libnexapipe_client.so: that is what IrohProxy.kt loads.
      3. Verify     - the copy is confirmed by size/mtime, and the fresh .so is scanned
                      for the JNI entry points the app calls. A .so built without the
                      tun-proxy feature has no nativeStartTunProxy and the VPN dies with
                      UnsatisfiedLinkError, which is otherwise only visible on device.
      4. Install    - gradlew :app:installDebug.
      5. Launch     - clear the log buffer, start com.nexa.pipe/.MainActivity, then run a
                      short smoke check over the buffer (native library load, Rust panic).
      6. Log        - stream logcat for the app's tags into a log file until Ctrl+C.

    Every stage can be skipped, so the script doubles as "build only" (-BuildOnly) or
    "just stream the logs" (-SkipRust -SkipInstall -SkipLaunch). Note that establishing
    the VPN itself still needs a manual tap: Android shows a VpnService.prepare dialog
    that no adb command can accept.

.PARAMETER Serial
    adb device serial. Only needed when more than one device is attached.

.PARAMETER Features
    cargo features for nexapipe-client. Default: jni,tun-proxy. tun-proxy implies
    local-proxy and is what compiles the TUN entry points. Override with a single
    feature only for experiments.

.PARAMETER LogFile
    Where the logcat capture is written; overwritten on every run. Defaults to
    <repo>\nexa_vpn_log.txt.

.PARAMETER SkipRust
    Keep the existing target/<target>/release/libnexapipe_client.so, do not rebuild it.

.PARAMETER SkipInstall
    Do not run gradlew installDebug.

.PARAMETER SkipLaunch
    Do not start the activity (the start-up smoke check is skipped as well).

.PARAMETER Restart
    Force-stop the app before launching, so the capture contains a cold start. Without
    it a warm launch produces no "Native library loaded" line and the smoke check stays
    inconclusive.

.PARAMETER NoLog
    Do not start the logcat streaming step.

.PARAMETER BuildOnly
    Shorthand for -SkipInstall -SkipLaunch -NoLog: build and validate the .so and stop.

.PARAMETER Check
    Preflight only: print the resolved toolchain and device, then exit. Useful when a
    build fails for environmental reasons.

.EXAMPLE
    .\run_android.ps1
    Full loop on the single attached device.

.EXAMPLE
    .\run_android.ps1 -Restart -Serial emulator-5554
    Cold start on a specific device, then stream the logs.

.EXAMPLE
    .\run_android.ps1 -BuildOnly
    Just rebuild and verify the Android cdylib.

.EXAMPLE
    .\run_android.ps1 -SkipRust -SkipInstall -SkipLaunch
    Only stream logcat (e.g. while reproducing a bug by hand).
#>
[CmdletBinding()]
param(
    [string]   $Serial,
    [string[]] $Features = @('jni', 'tun-proxy'),
    [string]   $LogFile,
    [switch]   $SkipRust,
    [switch]   $SkipInstall,
    [switch]   $SkipLaunch,
    [switch]   $Restart,
    [switch]   $NoLog,
    [switch]   $BuildOnly,
    [switch]   $Check
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants that must agree with the rest of the repo
# ---------------------------------------------------------------------------
$RustTarget = 'aarch64-linux-android'   # only ABI the app ships (build.gradle.kts abiFilters)
$Abi        = 'arm64-v8a'               # jniLibs subdirectory for that triple
$SoFileName = 'libnexapipe_client.so'   # IrohProxy.kt: System.loadLibrary("nexapipe_client")
$AppId      = 'com.nexa.pipe'
$Activity   = 'com.nexa.pipe/.MainActivity'

# Log tags: the Kotlin classes plus the Rust side, which initialises android_logger
# with the tag "NexaVpnService" in jni.rs.
$LogTags = @('NexaVpnService', 'IrohProxy', 'VpnViewModel', 'PermissionManager')

# JNI entry points the app needs. nativeStartTunProxy/nativeStopTunProxy only exist when
# the crate is compiled with the tun-proxy feature.
$RequiredSymbols = @(
    'Java_com_nexa_pipe_IrohProxy_nativeInit',
    'Java_com_nexa_pipe_IrohProxy_nativeStartIroh',
    'Java_com_nexa_pipe_IrohProxy_nativeStartProxy',
    'Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy',
    'Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy'
)

# ---------------------------------------------------------------------------
# Paths (derived from the script location, so the script works from any cwd)
# ---------------------------------------------------------------------------
$RepoRoot      = $PSScriptRoot
$AndroidDir    = [IO.Path]::Combine($RepoRoot, 'ui-android')
$JniLibDir     = [IO.Path]::Combine($AndroidDir, 'app', 'src', 'main', 'jniLibs', $Abi)
$SoSource      = [IO.Path]::Combine($RepoRoot, 'target', $RustTarget, 'release', $SoFileName)
$SoDest        = [IO.Path]::Combine($JniLibDir, $SoFileName)
$GradleWrapper = [IO.Path]::Combine($AndroidDir, 'gradlew.bat')
$NdkConfigFile = [IO.Path]::Combine($RepoRoot, '.cargo', 'config.toml')
$LocalProps    = [IO.Path]::Combine($AndroidDir, 'local.properties')
if (-not $LogFile) { $LogFile = [IO.Path]::Combine($RepoRoot, 'nexa_vpn_log.txt') }

if ($BuildOnly) {
    $SkipInstall = $true
    $SkipLaunch  = $true
    $NoLog       = $true
}

# ---------------------------------------------------------------------------
# Output helpers (same shape as ui-android/scripts/verify-signing-secrets.ps1)
# ---------------------------------------------------------------------------
function Write-Step { param([string]$m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Bad  { param([string]$m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Stop-Script {
    param([string]$m)
    Write-Bad $m
    exit 1
}

# ---------------------------------------------------------------------------
# Native command wrappers
#
# Two reasons not to call native commands directly from the script body:
#  - $ErrorActionPreference is "Stop" here, but PowerShell 5.1 promotes a native
#    command's stderr to a terminating NativeCommandError while that preference is in
#    effect, and cargo, Gradle and adb all write progress/warnings to stderr. Assigning
#    the preference inside a function is function-scoped, so these wrappers see
#    "Continue" while the rest of the script keeps fail-fast cmdlet behaviour.
#  - Success then has to be judged from the exit code, which is centralised here.
# ---------------------------------------------------------------------------
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]   $Label,
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $Arguments,
        [string] $StdOutFile
    )
    Write-Host "  `$ $Exe $($Arguments -join ' ')" -ForegroundColor DarkGray
    $ErrorActionPreference = 'Continue'
    if ($StdOutFile) {
        & $Exe @Arguments | Out-File -FilePath $StdOutFile -Encoding utf8
    } else {
        & $Exe @Arguments
    }
    $code = $LASTEXITCODE
    if ($code -ne 0) { Stop-Script "$Label failed (exit code $code)" }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $Arguments
    )
    $ErrorActionPreference = 'Continue'
    $output = & $Exe @Arguments 2>&1
    $code = $LASTEXITCODE
    $lines = @()
    if ($output) { $lines = @($output | ForEach-Object { "$_" }) }
    return [pscustomobject]@{ ExitCode = $code; Lines = $lines }
}

# ---------------------------------------------------------------------------
# Toolchain discovery
# ---------------------------------------------------------------------------
function Get-FirstExistingPath {
    param([string[]]$Candidates)
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Get-Item -LiteralPath $c).FullName }
    }
    return $null
}

function Resolve-CommandPath {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# Android Studio writes local.properties; its sdk.dir is the most reliable pointer on a
# developer machine. Note the java-properties escaping (C\:\\Users\\...).
function Resolve-AndroidSdk {
    $candidates = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT)
    if (Test-Path -LiteralPath $LocalProps) {
        $hit = Select-String -LiteralPath $LocalProps -Pattern '^sdk\.dir=(.+)$' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) {
            $value = $hit.Matches[0].Groups[1].Value.Trim()
            $value = $value -replace '\\\\', '\' -replace '\\:', ':' -replace '\\=', '=' -replace '\\ ', ' '
            $candidates += $value
        }
    }
    return (Get-FirstExistingPath -Candidates $candidates)
}

# The NDK used for the C parts (ring is compiled through the cc crate) should be the same
# one .cargo/config.toml pins as the linker for this target; mixing two NDKs is a classic
# confusing link failure. So the pin wins when it is installed.
function Resolve-NdkHome {
    param([string]$SdkRoot)

    $pinnedNdk    = $null
    $pinnedLinker = $null
    if (Test-Path -LiteralPath $NdkConfigFile) {
        $hit = Select-String -LiteralPath $NdkConfigFile -Pattern '^\s*linker\s*=\s*"([^"]+)"' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) {
            $pinnedLinker = $hit.Matches[0].Groups[1].Value
            if ($pinnedLinker -match '[/\\]ndk[/\\]([^/\\]+)[/\\]') { $pinnedNdk = $Matches[1] }
        }
    }

    $fromEnv = $env:ANDROID_NDK_HOME
    if ($fromEnv -and (Test-Path -LiteralPath $fromEnv)) {
        $envVersion = Split-Path -Leaf $fromEnv
        if ($pinnedNdk -and $envVersion -ne $pinnedNdk) {
            Write-Warn "ANDROID_NDK_HOME=$envVersion differs from the NDK $pinnedNdk pinned in .cargo/config.toml"
        }
        Write-Ok "NDK $envVersion (ANDROID_NDK_HOME)"
        return (Get-Item -LiteralPath $fromEnv).FullName
    }

    if ($pinnedNdk) {
        $pinnedDir = [IO.Path]::Combine($SdkRoot, 'ndk', $pinnedNdk)
        if (Test-Path -LiteralPath $pinnedDir) {
            if ($pinnedLinker -and -not (Test-Path -LiteralPath $pinnedLinker)) {
                Write-Warn "The linker pinned in .cargo/config.toml is missing: $pinnedLinker"
            }
            Write-Ok "NDK $pinnedNdk (pinned by .cargo/config.toml)"
            return (Get-Item -LiteralPath $pinnedDir).FullName
        }
        Write-Warn "NDK $pinnedNdk is pinned in .cargo/config.toml but not installed; using the newest one below"
    }

    $installed = @()
    $ndkRoot = [IO.Path]::Combine($SdkRoot, 'ndk')
    if (Test-Path -LiteralPath $ndkRoot) {
        foreach ($dir in (Get-ChildItem -LiteralPath $ndkRoot -Directory)) {
            $parsed = $null
            if ([version]::TryParse($dir.Name, [ref]$parsed)) { $installed += $dir }
        }
    }
    if ($installed.Count -eq 0) {
        Stop-Script "No NDK found under $ndkRoot. Install one with the SDK manager or set ANDROID_NDK_HOME."
    }
    $newest = $installed | Sort-Object -Property { [version]$_.Name } -Descending | Select-Object -First 1
    Write-Warn "Using NDK $($newest.Name); consider pinning it in .cargo/config.toml so CC and the linker match"
    return $newest.FullName
}

function Resolve-Adb {
    param([string]$SdkRoot)
    if ($SdkRoot) {
        $candidate = [IO.Path]::Combine($SdkRoot, 'platform-tools', 'adb.exe')
        if (Test-Path -LiteralPath $candidate) { return (Get-Item -LiteralPath $candidate).FullName }
    }
    return (Resolve-CommandPath -Name 'adb')
}

function Get-ConnectedDevices {
    param([string]$Adb)
    $result = Invoke-NativeCapture -Exe $Adb -Arguments @('devices')
    if ($result.ExitCode -ne 0) {
        Stop-Script "adb devices failed:`n         $($result.Lines -join "`n         ")"
    }
    $devices = @()
    foreach ($line in $result.Lines) {
        if ($line -match '^(\S+)\s+(device|offline|unauthorized|no permissions)\s*$') {
            $devices += [pscustomobject]@{ Serial = $Matches[1]; State = $Matches[2] }
        }
    }
    return $devices
}

function Select-Device {
    param([string]$Adb, [string]$Requested)

    $devices = @(Get-ConnectedDevices -Adb $Adb)
    $usable  = @($devices | Where-Object { $_.State -eq 'device' })

    if ($Requested) {
        $match = $devices | Where-Object { $_.Serial -eq $Requested } | Select-Object -First 1
        if (-not $match) {
            $list = if ($devices.Count) { ($devices | ForEach-Object { "$($_.Serial) [$($_.State)]" }) -join ', ' } else { 'none' }
            Stop-Script "Device '$Requested' is not attached (attached: $list)"
        }
        if ($match.State -ne 'device') {
            Stop-Script "Device '$Requested' is in state '$($match.State)'; unlock it / accept the debugging prompt and retry"
        }
        return $match.Serial
    }

    if ($usable.Count -eq 1) { return $usable[0].Serial }
    if ($usable.Count -gt 1) {
        Stop-Script ("More than one usable device; pass -Serial one of: " + (($usable | ForEach-Object { $_.Serial }) -join ', '))
    }

    $detail = if ($devices.Count) { ($devices | ForEach-Object { "$($_.Serial) [$($_.State)]" }) -join ', ' } else { 'no device detected' }
    Stop-Script @"
No usable adb device ($detail).
         - physical device: enable USB debugging, plug it in, accept the RSA prompt
         - emulator: start an arm64 image first (the app is arm64-v8a only)
         To only build the cdylib without a device, run: .\run_android.ps1 -BuildOnly
"@
}

# ---------------------------------------------------------------------------
# .so validation
# ---------------------------------------------------------------------------
# Reading the file as ASCII and looking for the symbol names is enough to answer "was this
# built with the right features"; llvm-nm from the NDK would be the alternative, but the
# dynamic symbol table contains the names verbatim anyway.
function Get-MissingExports {
    param([string]$Path, [string[]]$Symbols)
    $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path))
    $missing = @()
    foreach ($s in $Symbols) {
        if (-not $text.Contains($s)) { $missing += $s }
    }
    return $missing
}

function Get-FileSha256 {
    param([string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLower()
    } finally { $sha.Dispose() }
}

function Get-LogcatFilters {
    $specs = @()
    foreach ($t in $LogTags) { $specs += "${t}:V" }
    # Crashes and process kills are not tagged with our names; keep those two useful
    # and silence everything else with *:S.
    $specs += 'AndroidRuntime:E'
    $specs += 'ActivityManager:W'
    $specs += '*:S'
    return $specs
}

# ---------------------------------------------------------------------------
# 1. Preflight
# ---------------------------------------------------------------------------
Write-Host "nexapipe android debug loop" -ForegroundColor White
Write-Step "Preflight"

$cargo    = Resolve-CommandPath -Name 'cargo'
$cargoNdk = Resolve-CommandPath -Name 'cargo-ndk'
if (-not $cargo)    { Stop-Script "cargo not found on PATH" }
if (-not $cargoNdk) { Stop-Script "cargo-ndk not found; install it with: cargo install cargo-ndk" }

$sdkRoot = Resolve-AndroidSdk
if (-not $sdkRoot) {
    Stop-Script "Android SDK not found (set ANDROID_HOME or add sdk.dir to ui-android/local.properties)"
}
$ndkHome = Resolve-NdkHome -SdkRoot $sdkRoot
$adb     = Resolve-Adb -SdkRoot $sdkRoot

Write-Ok "cargo      : $cargo"
Write-Ok "cargo-ndk  : $cargoNdk"
Write-Ok "SDK        : $sdkRoot"
Write-Ok "NDK        : $ndkHome"
if ($env:JAVA_HOME) {
    Write-Ok "JAVA_HOME  : $env:JAVA_HOME"
} else {
    Write-Warn "JAVA_HOME is not set; gradlew.bat may refuse to start"
}

# cargo-ndk resolves the NDK from the environment, so make the choice explicit. Both
# variables are set because this machine already defines NDK_HOME separately; when the two
# disagree cargo-ndk warns and it is unclear which NDK supplied the C compiler.
$env:ANDROID_NDK_HOME = $ndkHome
$env:NDK_HOME         = $ndkHome
$env:ANDROID_HOME     = $sdkRoot

$needDevice = (-not $SkipInstall) -or (-not $SkipLaunch) -or (-not $NoLog)
$device = $null
if ($needDevice -or $Check) {
    if (-not $adb) {
        if ($Check) { Write-Warn "adb not found under $sdkRoot\platform-tools" }
        else        { Stop-Script "adb not found; install the platform-tools package of the SDK" }
    } else {
        Write-Ok "adb        : $adb"
    }
}
if ($adb) {
    if ($Check) {
        $devices = @(Get-ConnectedDevices -Adb $adb)
        if ($devices.Count) {
            foreach ($d in $devices) { Write-Ok "device     : $($d.Serial) [$($d.State)]" }
        } else {
            Write-Warn "no adb device attached"
        }
    } elseif ($needDevice) {
        $device = Select-Device -Adb $adb -Requested $Serial
        Write-Ok "device     : $device"
    }
}

if ($Check) {
    Write-Step "Reusing the last build"
    if (Test-Path -LiteralPath $SoSource) {
        $fi = Get-Item -LiteralPath $SoSource
        Write-Ok "target .so : $($fi.Name), $($fi.Length) bytes, $($fi.LastWriteTime)"
        $missing = @(Get-MissingExports -Path $SoSource -Symbols $RequiredSymbols)
        if ($missing.Count) {
            Write-Warn "missing exports: $($missing -join ', ')"
            Write-Warn "rebuild with -Features jni,tun-proxy"
        } else {
            Write-Ok "all required JNI entry points present"
        }
    } else {
        Write-Warn "no build yet at $SoSource"
    }
    if (Test-Path -LiteralPath $SoDest) {
        Write-Ok "jniLibs    : $SoDest"
    } else {
        Write-Warn "jniLibs empty ($SoDest); the APK would have no native library"
    }
    Write-Host ""
    exit 0
}

# ---------------------------------------------------------------------------
# 2. Build the Rust cdylib and install it into the Android project
# ---------------------------------------------------------------------------
if (-not $SkipRust) {
    Write-Step "Building the client cdylib ($RustTarget, features: $($Features -join ','))"
    # Run from the repo root so the root .cargo/config.toml (target linker) applies.
    Push-Location $RepoRoot
    try {
        # --package, not -p: after "build" every argument is forwarded to cargo, but the
        # short -p would be ambiguous with cargo-ndk's own --platform option.
        Invoke-Native -Label 'cargo ndk build' -Exe $cargo -Arguments @(
            'ndk', '--target', $RustTarget, 'build', '--release',
            '--package', 'nexapipe-client', '--features', ($Features -join ',')
        )
    } finally {
        Pop-Location
    }
    Write-Ok "cargo ndk build finished"
} else {
    Write-Step "Skipping the Rust build (-SkipRust); reusing $SoSource"
    if (-not (Test-Path -LiteralPath $SoSource)) {
        Stop-Script "No existing .so at $SoSource, drop -SkipRust"
    }
}

if (-not (Test-Path -LiteralPath $SoSource)) {
    Stop-Script "cargo reported success but $SoSource does not exist"
}
$srcInfo = Get-Item -LiteralPath $SoSource
Write-Ok "$($srcInfo.Name): $($srcInfo.Length) bytes, $($srcInfo.LastWriteTime)"

# ---------------------------------------------------------------------------
# 3. Validate the .so and copy it in
# ---------------------------------------------------------------------------
Write-Step "Validating the cdylib"
$missing = @(Get-MissingExports -Path $SoSource -Symbols $RequiredSymbols)
if ($missing.Count) {
    Write-Bad "Missing JNI entry points: $($missing -join ', ')"
    Write-Host "         The app would fail with UnsatisfiedLinkError at runtime." -ForegroundColor DarkGray
    Write-Host "         Rebuild with the default features (jni,tun-proxy); tun-proxy is what" -ForegroundColor DarkGray
    Write-Host "         compiles the TUN entry points." -ForegroundColor DarkGray
    exit 1
}
Write-Ok "all required JNI entry points present"
Write-Ok ("sha256 {0}" -f (Get-FileSha256 -Path $SoSource))

if (-not (Test-Path -LiteralPath $JniLibDir)) {
    New-Item -ItemType Directory -Path $JniLibDir -Force | Out-Null
}
Copy-Item -LiteralPath $SoSource -Destination $SoDest -Force
$dstInfo = Get-Item -LiteralPath $SoDest
# The copy is verified rather than assumed: a wrong or partially written .so would only
# surface as a confusing crash on the device.
if ($dstInfo.Length -ne $srcInfo.Length -or $dstInfo.LastWriteTimeUtc -ne $srcInfo.LastWriteTimeUtc) {
    Stop-Script "Copy verification failed: $SoDest ($($dstInfo.Length) bytes) != source ($($srcInfo.Length) bytes)"
}
Write-Ok "installed into $JniLibDir"

# ---------------------------------------------------------------------------
# 4. Install the debug APK
# ---------------------------------------------------------------------------
if (-not $SkipInstall) {
    Write-Step "gradlew :app:installDebug"
    if (-not (Test-Path -LiteralPath $GradleWrapper)) {
        Stop-Script "gradlew.bat not found at $GradleWrapper (is ui-android a checked-out submodule?)"
    }
    Invoke-Native -Label 'gradlew installDebug' -Exe $GradleWrapper -Arguments @('-p', $AndroidDir, ':app:installDebug')
    Write-Ok "installed $AppId on $device"
} else {
    Write-Step "Skipping the APK install (-SkipInstall)"
}

# ---------------------------------------------------------------------------
# 5. Clear the buffer, launch, smoke check
# ---------------------------------------------------------------------------
if (-not $SkipLaunch) {
    Write-Step "Launching $Activity"

    # Clear before the launch, not after: the original script cleared afterwards and threw
    # away exactly the start-up lines that matter (native library load, proxy start).
    if (-not $NoLog) {
        Invoke-Native -Label 'logcat -c' -Exe $adb -Arguments @('-s', $device, 'logcat', '-c')
        Write-Ok "log buffer cleared"
    }

    if ($Restart) {
        Invoke-Native -Label 'am force-stop' -Exe $adb -Arguments @('-s', $device, 'shell', 'am', 'force-stop', $AppId)
        Start-Sleep -Milliseconds 500
        Write-Ok "app force-stopped for a cold start"
    }

    $launch = Invoke-NativeCapture -Exe $adb -Arguments @('-s', $device, 'shell', 'am', 'start', '-W', '-n', $Activity)
    foreach ($line in $launch.Lines) { Write-Host "         $line" -ForegroundColor DarkGray }
    if (($launch.Lines -join "`n") -match 'Error(:| type)') {
        Stop-Script "am start failed for $Activity"
    }
    Write-Ok "activity started"

    if (-not $NoLog) {
        Write-Step "Start-up smoke check"
        # Poll the buffer instead of sleeping blindly: the process needs a moment to load
        # the library, and a missing symbol shows up within the first second.
        $failure = 'RUST PANIC|UnsatisfiedLinkError|Failed to load native library|No implementation found for|FATAL EXCEPTION'
        $deadline = (Get-Date).AddSeconds(15)
        $loaded = $null
        $buffer = @()
        while ((Get-Date) -lt $deadline) {
            $dump   = Invoke-NativeCapture -Exe $adb -Arguments (@('-s', $device, 'logcat', '-d', '-v', 'brief') + (Get-LogcatFilters))
            $buffer = $dump.Lines
            $text   = $buffer -join "`n"
            if ($text -match $failure) { $loaded = $false; break }
            if ($text -match 'Native library loaded successfully') { $loaded = $true; break }
            Start-Sleep -Milliseconds 700
        }

        $pidDump = Invoke-NativeCapture -Exe $adb -Arguments @('-s', $device, 'shell', 'pidof', $AppId)
        $appPid  = (($pidDump.Lines -join ' ').Trim())

        if ($loaded -eq $false) {
            Write-Bad "the app logged a start-up failure:"
            $buffer | Where-Object { $_ -match $failure } | Select-Object -Last 15 |
                ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
        } elseif ($loaded -eq $true) {
            Write-Ok "native library loaded (pid $appPid)"
        } else {
            Write-Warn "no 'Native library loaded' line in the buffer - the app was probably already running; try -Restart"
        }
        if (-not $appPid) {
            Write-Warn "$AppId is not running; check the capture below for the crash reason"
        }
    }
} else {
    Write-Step "Skipping the launch (-SkipLaunch)"
}

# ---------------------------------------------------------------------------
# 6. Stream logcat
# ---------------------------------------------------------------------------
if ($NoLog) {
    Write-Step "Done (-NoLog)"
    exit 0
}
if (-not $device) {
    Stop-Script "Cannot capture logs without a device"
}

Write-Step "Capturing logcat -> $LogFile"
Write-Host "  Tags: $($LogTags -join ', ') (+ AndroidRuntime:E, ActivityManager:W)" -ForegroundColor DarkGray
Write-Host "  Press Ctrl+C to stop. Accept the VpnService.prepare dialog on the device to" -ForegroundColor DarkGray
Write-Host "  actually bring the tunnel up - adb cannot tap it for you." -ForegroundColor DarkGray
Write-Host "  Follow the file live in another window with:" -ForegroundColor DarkGray
Write-Host "      Get-Content `"$LogFile`" -Wait -Tail 50" -ForegroundColor DarkGray

$logArgs = @('-s', $device, 'logcat', '-v', 'time') + (Get-LogcatFilters)
# logcat emits UTF-8. PowerShell decodes a native command's stdout with the console output
# encoding, so on a non-UTF-8 console (code page 936 here) any non-ASCII log line would end
# up garbled in the file. Scoped to this step: the Gradle/adb chatter above follows the
# console code page instead.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
# The file is overwritten on every run (Out-File truncates), so no delete is needed.
Invoke-Native -Label 'logcat' -Exe $adb -Arguments $logArgs -StdOutFile $LogFile

Write-Host ""
Write-Ok "capture stopped; $((Get-Item -LiteralPath $LogFile).Length) bytes in $LogFile"
