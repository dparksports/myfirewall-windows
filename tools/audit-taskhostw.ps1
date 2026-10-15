<#
  audit-taskhostw.ps1 - genuineness + DLL-attribution auditor for taskhostw.exe
  (the taskhostw analog of audit-svchost.ps1 from the svchost triage session).

  svchost triage pivots on PID -> hosted SCM service (tasklist /svc), because Windows
  Firewall can scope a rule to a service inside the shared svchost image
  (New-NetFirewallRule -Service). taskhostw.exe hosts scheduled-task COM handlers
  instead: each instance is launched as "taskhostw.exe {CLSID}", and the CLSID
  resolves through HKLM/HKCU SOFTWARE\Classes\CLSID\{...}\InprocServer32 to the DLL
  actually loaded in-process. This script performs that pivot:

    1. instance inventory  - every taskhostw PID with its full command line
    2. handler attribution - CLSID -> InprocServer32 DLL (HKCU, HKLM 64/32-bit views)
    3. task attribution    - scheduled tasks whose ComHandler ClassId matches
    4. loaded modules      - every DLL inside each instance
    5. live sockets        - remote endpoints each instance is talking to
    6. genuineness checks  - path, signature, parent, session (masquerade defeat)

  Any single genuineness FAIL = SUSPICIOUS (a fake taskhostw cannot fake the
  CLSID->task mapping, the Microsoft signature, or SCM parentage simultaneously).

  Usage:  powershell -ExecutionPolicy Bypass -File audit-taskhostw.ps1 [-Pid <pid>] [-All]
          default (no args): audits ALL running instances.
          Elevated recommended (System session instances hide command lines otherwise).
#>
param(
    [int]$ProcId = -1,
    [switch]$All
)
$ErrorActionPreference = 'Continue'

function Test-Clsid([string]$s) {
    $s -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
}

function Resolve-ClsidDll([string]$clsid, [string]$ownerSid = '') {
    # Probe the querying user's HKCU, HKLM (64/32-bit), and - when the instance runs
    # as another user - that owner's HKU hive (per-user handlers register there).
    $probes = @(
        "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32",
        "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32",
        "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$clsid\InprocServer32"
    )
    if ($ownerSid) { $probes += "Registry::HKEY_USERS\$ownerSid\Software\Classes\CLSID\$clsid\InprocServer32" }
    foreach ($probe in $probes) {
        if (Test-Path $probe) {
            $dll = (Get-ItemProperty $probe -ErrorAction SilentlyContinue).'(default)'
            if ($dll) { return [Environment]::ExpandEnvironmentVariables("$dll".Trim('"')) }
        }
    }
    return $null
}

# Scheduled tasks with COM-handler actions: CLSID -> task paths
function Get-ComHandlerMap {
    $map = @{}
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $stack = New-Object System.Collections.Stack
        $stack.Push($svc.GetFolder("\"))
        while ($stack.Count -gt 0) {
            $folder = $stack.Pop()
            foreach ($task in @($folder.GetTasks(0))) {
                try {
                    foreach ($action in @($task.Definition.Actions)) {
                        try {
                            if ($action.Type -eq 5 -and $action.ClassId) {   # 5 = TASK_ACTION_COM_HANDLER
                                $map[$action.ClassId] = @($map[$action.ClassId]) + $task.Path | Where-Object { $_ }
                            }
                        } catch { }
                    }
                } catch { }
            }
            foreach ($sub in @($folder.GetFolders(0))) { $stack.Push($sub) }
        }
    } catch {
        Write-Warning "Task enumeration failed: $($_.Exception.Message)"
    }
    return $map
}

Write-Host " taskhostw.exe audit - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') " -ForegroundColor Cyan
$comMap = Get-ComHandlerMap
Write-Host "COM-handler tasks enumerated: $($comMap.Count) distinct CLSIDs`n"

$procs = if ($ProcId -gt 0) { Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" }
         else            { Get-CimInstance Win32_Process -Filter "Name='taskhostw.exe'" }

if (-not $procs) { Write-Host "No taskhostw.exe instances matched." -ForegroundColor Yellow; exit 0 }

foreach ($p in $procs) {
    Write-Host "--- PID $($p.ProcessId) -----------------------------------" -ForegroundColor Cyan
    Write-Host "  Command line : $(if ($p.CommandLine) { $p.CommandLine } else { '(hidden - run elevated)' })"
    Write-Host "  Image path   : $(if ($p.ExecutablePath) { $p.ExecutablePath } else { '(hidden - run elevated)' })"

    # Unlike svchost (always session 0), taskhostw runs BOTH in session 0 for
    # machine tasks AND in the user's session for per-user tasks - informational.
    $ownerSid = try { ($p | Invoke-CimMethod -MethodName GetOwnerSid).Sid } catch { '' }
    Write-Host "  SessionId    : $($p.SessionId)   Owner SID: $ownerSid"

    # Handler attribution
    $tokens = @()
    if ($p.CommandLine) { $tokens = @($p.CommandLine -split '\s+' | Where-Object { $_ -and $_ -ne '"taskhostw.exe"' }) }
    $clsid = $null; $dllArg = $null
    for ($i = 1; $i -lt $tokens.Count; $i++) {
        if (Test-Clsid $tokens[$i]) { $clsid = $tokens[$i]; break }
        if ($tokens[$i] -ieq '-dllname' -and $i + 1 -lt $tokens.Count) { $dllArg = $tokens[$i + 1] }
    }
    if ($clsid) {
        Write-Host "  Handler CLSID: $clsid"
        $dll = Resolve-ClsidDll $clsid $ownerSid
        if ($dll) {
            Write-Host "  -> DLL        : $dll"
        } else {
            # Normal for OS-internal contracts: the Task Scheduler's own CLSID
            # {222A245B-E637-4AE9-A93F-A59CA119A75E} is hard-coded, not registered.
            Write-Host "  -> DLL        : not registry-resolved (OS-internal contract or reg-free COM)" -ForegroundColor Yellow
        }
        if ($comMap.ContainsKey($clsid)) {
            Write-Host "  -> Task(s)    : $($comMap[$clsid] -join ', ')"
        } else {
            Write-Host "  -> Task(s)    : none matched (OS-internal or unregistered handler)" -ForegroundColor Yellow
        }
    } elseif ($dllArg) {
        Write-Host "  Handler DLL  : $dllArg (-dllname launch)"
    } else {
        Write-Host "  Handler      : (no CLSID/-dllname argument on command line)" -ForegroundColor Yellow
    }

    # Loaded modules (the DLLs actually hosted in-process)
    try {
        $proc = Get-Process -Id $p.ProcessId -ErrorAction Stop
        $dlls = @($proc.Modules | Where-Object { $_.FileName -notlike '*.exe' } | ForEach-Object { $_.FileName })
        Write-Host "  Modules      : $($dlls.Count) DLLs loaded"
        $dlls | Sort-Object | Select-Object -First 12 | ForEach-Object { Write-Host "      $_" }
        if ($dll -and $dlls -notcontains $dll) { Write-Host "      (resolved handler DLL not yet loaded - task idle or exited)" -ForegroundColor DarkGray }
        $proc.Dispose()
    } catch { Write-Host "  Modules      : (enumeration failed: $($_.Exception.Message))" -ForegroundColor DarkGray }

    # Live sockets owned by this instance
    $sockets = @(netstat -ano -p tcp | Select-String "\s+$($p.ProcessId)\s*$" | ForEach-Object { "$($_.Line.Trim())" })
    if ($sockets.Count -gt 0) {
        Write-Host "  Sockets      : $($sockets.Count) TCP endpoint(s):" -ForegroundColor Yellow
        $sockets | Select-Object -First 6 | ForEach-Object { Write-Host "      $_" }
    } else {
        Write-Host "  Sockets      : none (idle)"
    }

    # -- Genuineness checks (masquerade defeat) --
    # taskhostw-appropriate checks: path, signature, parentage. The svchost
    # session-0 rule does NOT apply (per-user tasks run in the user's session),
    # and an unregistered CLSID is not itself malicious (OS-internal contracts
    # are hard-coded) - both stay informational above.
    $verdict = 'NORMAL'
    $path = $p.ExecutablePath
    if ($path -and $path -notlike "$env:SystemRoot\System32\taskhostw.exe" -and $path -notlike "$env:SystemRoot\SysWOW64\taskhostw.exe") {
        Write-Host "  FAIL  PATH outside System32/SysWOW64: $path" -ForegroundColor Red; $verdict = 'SUSPICIOUS'
    }
    if ($path -and (Test-Path $path)) {
        $sig = Get-AuthenticodeSignature $path
        if ($sig.Status -ne 'Valid') { Write-Host "  FAIL  SIGNATURE $($sig.Status)" -ForegroundColor Red; $verdict = 'SUSPICIOUS' }
        else { Write-Host "  OK  Signed by: $($sig.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1')" -ForegroundColor Green }
    }
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
    if ($parent -and $parent.Name -ne 'svchost.exe') {
        Write-Host "  FAIL  PARENT $($parent.Name) (legit parent is svchost.exe hosting Schedule)" -ForegroundColor Red; $verdict = 'SUSPICIOUS'
    }
    Write-Host "  VERDICT      : $verdict`n" -ForegroundColor $(if ($verdict -eq 'NORMAL') { 'Green' } else { 'Red' })
}

Write-Host @"
Notes
  * WFP cannot scope a firewall rule to one DLL inside taskhostw (no per-task
    equivalent of -Service). Attribution answers WHO transmits; blocking is
    image-level (the app's block-by-name covers every path of taskhostw.exe).
  * Suspicious signals: unsigned / non-System32 image, non-svchost parent,
    sockets active for an instance whose handler resolves to nothing. The
    Task Scheduler's own CLSID {222A245B-...-A59CA119A75E} is hard-coded (not
    in the registry) - its appearance on the command line is normal.
"@ -ForegroundColor DarkGray
