# Tracking the DLLs inside taskhostw.exe — the svchost approach, adapted

**Companion to:** `SVCHOST-TRIAGE-REPORT.md` (svchost session) · `tools/audit-taskhostw.ps1`
(machine auditor) · `MyFirewall.Desktop/Services/TaskHostDllTracker.cs` (live in-app panel)

---

## 1. Why taskhostw needs a different pivot than svchost

The svchost triage settled on `tasklist /svc` (PID → hosted SCM service) as "the triage
pivot" — it turns "svchost talking to the internet" into "WpnService talking to Azure."
That pivot exists because WFP gives svchost special treatment: a firewall rule can name a
**service** (`New-NetFirewallRule -Service`, `INetFwRule.serviceName`) and the filter
engine matches the service SID inside the shared host process. That's how
`Set-SvchostAllowlist.ps1` scopes WpnService to Microsoft ranges without touching DoSvc.

taskhostw.exe has **no equivalent scope**. It hosts *scheduled-task COM handlers*, not
SCM services:

| | svchost.exe | taskhostw.exe |
|---|---|---|
| hosts | SCM services (DLLs from `ServiceDll`) | scheduled-task COM handlers (DLLs from `InprocServer32`) |
| launched by | SCM | Task Scheduler (svchost hosting the `Schedule` service) |
| instance identity | `-k <group>` / per-service | `taskhostw.exe {CLSID}` — one CLSID per hosted handler |
| firewall scoping | per-service (`-Service`) | **none** — only the whole image or remote addresses |

So for "users don't want taskhostw.exe transmitting anywhere": **blocking** is
image-level (block-by-name covers every path taskhostw.exe exists at — see
`ProcessBlockListService`). **Attribution** — which DLL inside it would have been
transmitting — is what this feature provides, and it chains three lookups:

```
PID --command line--> {CLSID} --registry InprocServer32--> DLL path
                        '--Schedule.Service--> owning task name(s)
PID --Process.Modules--> every DLL actually loaded in-process
PID --socket table----> live remote endpoints
```

## 2. Where each fact comes from

**Command line (the CLSID).** Task Scheduler launches `taskhostw.exe {CLSID}`. The
command line of another process is read natively:
`NtQueryInformationProcess(ProcessBasicInformation)` → PEB → `ProcessParameters` →
`CommandLine` UNICODE_STRING (x64 offsets; the app is win-x64). This is the same
technique Process Explorer uses, needs no WMI, and works elevated for other-session
instances. (The audit script uses `Win32_Process.CommandLine` — CIM does the same read.)

**CLSID → DLL.** `HKCU/HKLM SOFTWARE\Classes\CLSID\{...}\InprocServer32` (default
value), probing HKLM in both 64-bit and 32-bit views plus the owner user's
`HKU\<SID>\Software\Classes` hive for per-user handlers.

**CLSID → task.** The Task Scheduler COM API (`Schedule.Service`), walked recursively:
every task whose action is a COM handler (`TASK_ACTION_COM_HANDLER`, type 5) exposes a
`ClassId`; a reverse map CLSID → task paths turns the bare GUID into a name a human
recognizes ("\Microsoft\Windows\...").

**DLLs actually loaded.** `Process.Modules` on each PID — the ground truth of what code
is running inside the instance right now, which catches handlers the registry didn't
resolve.

**Traffic join.** The app's existing connection table already carries owning PIDs; a
join answers "is this instance transmitting" per instance, not just per image.

## 3. What the live machine taught us (fail-path testing, svchost-style)

The first draft of the auditor reused two svchost checks verbatim — both wrong for
taskhostw, both caught by running against a genuine stock instance:

1. **"Session 0 or suspicious" is an svchost rule.** taskhostw legitimately runs in the
   *user's* session for per-user tasks (this machine: session 1, user SID visible).
   The check was removed; session is informational.
2. **"CLSID not registered = red flag" false-positives on every stock machine.** The
   Task Scheduler's own contract CLSID `{222A245B-E637-4AE9-A93F-A59CA119A75E}`
   (observed live) is hard-coded, registered in no CLSID hive. Unresolved CLSIDs are
   now an attribution gap (yellow note), not a verdict. Genuineness rests on the three
   checks that actually discriminate: **path** (System32/SysWOW64), **signature**
   (Valid, Microsoft Windows), **parent** (svchost.exe hosting Schedule).

The corrected script returns NORMAL for the genuine instance while still failing the
masquerade paths (a copied taskhostw in %TEMP% fails PATH; a hollowed one fails
SIGNATURE; an attacker-spawned one fails PARENT).

## 4. Honest limitations

- **No per-DLL firewall scope.** WFP matches the executing image; a hosted DLL cannot
  be blocked alone. If one task's DLL must be allowed while taskhostw is otherwise
  blocked, the mechanisms are: allow rules for specific remote addresses (allow beats
  block in WFP), or disabling the owning scheduled task (outside this feature).
- **Reg-free / manifest COM.** Handlers registered only via application manifests
  (reg-free COM) resolve to nothing in the CLSID hives; the loaded-modules list is the
  fallback for those instances.
- **Send-and-die attribution.** Short-lived taskhostw instances can exit before a
  snapshot; the ETW PID→image map (already in `NetworkMonitorService`) covers the
  socket side, and the panel refreshes every sweep (~30 s).

## 5. Using it

```powershell
# Full audit of every instance (read-only)
powershell -ExecutionPolicy Bypass -File tools\audit-taskhostw.ps1

# One PID
powershell -ExecutionPolicy Bypass -File tools\audit-taskhostw.ps1 -ProcId 2740
```

In the Desktop app: the **🧬 Task Host DLLs** sidebar panel shows each live instance
with its handler, resolved DLL, owning task(s), and connection count, refreshed on the
reconciliation sweep. Blocking taskhostw.exe entirely: type its name in the Blocked
panel's input — every location is ruled at once and watched for new copies.
