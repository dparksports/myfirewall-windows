using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MyFirewall.Desktop.Models;

namespace MyFirewall.Desktop.Services
{
    /// <summary>
    /// Tracks which task DLLs run inside taskhostw.exe — the taskhostw analog of the
    /// svchost PID→service triage pivot.
    ///
    /// svchost.exe hosts SCM services, and Windows Firewall can scope rules to a
    /// service inside the shared host (INetFwRule.serviceName / -Service). taskhostw.exe
    /// hosts scheduled-task COM handlers instead: Task Scheduler launches
    /// "taskhostw.exe {CLSID}", and the CLSID resolves through
    /// HKLM/HKCU SOFTWARE\Classes\CLSID\{...}\InprocServer32 to the DLL actually loaded
    /// in-process. Scheduled tasks are not SCM services and get no per-task firewall
    /// scope, so this tracker answers the question WFP cannot: WHICH task DLL is
    /// transmitting, when all connections belong to the same taskhostw.exe image.
    /// </summary>
    public class TaskHostDllTracker
    {
        private readonly Action<string> _logError;

        private static readonly Regex ClsidPattern = new(
            @"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$",
            RegexOptions.Compiled);

        // CLSID → scheduled-task paths (COM-handler actions only); rebuilt per snapshot.
        private Dictionary<string, List<string>>? _comHandlerMap;
        private DateTime _mapBuiltAt;
        private readonly object _snapshotLock = new();

        public TaskHostDllTracker(Action<string> logError)
        {
            _logError = logError;
        }

        public List<TaskHostDllEntry> Snapshot(List<ConnectionInfo> liveConnections)
        {
            lock (_snapshotLock)
            {
                return SnapshotUnsafe(liveConnections);
            }
        }

        private List<TaskHostDllEntry> SnapshotUnsafe(List<ConnectionInfo> liveConnections)
        {
            var entries = new List<TaskHostDllEntry>();
            var connectionCounts = liveConnections
                .GroupBy(c => c.PID)
                .ToDictionary(g => g.Key, g => g.Count());

            try
            {
                // The task-folder walk is the slow part (COM, potentially hundreds of
                // tasks) — cache the map for five minutes instead of walking per sweep.
                if (_comHandlerMap is null || (DateTime.Now - _mapBuiltAt).TotalMinutes > 5)
                {
                    _comHandlerMap = BuildComHandlerMap();
                    _mapBuiltAt = DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                _logError($"TaskHostDllTracker.BuildComHandlerMap: {ex.Message}");
                _comHandlerMap = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            }

            foreach (var pid in GetTaskHostPids())
            {
                try
                {
                    string cmdLine = GetCommandLine(pid) ?? "";
                    string? clsid = ParseClsid(cmdLine, out string dllArg);

                    string dllPath = "";
                    if (clsid != null) dllPath = ResolveClsidDll(clsid) ?? "";
                    if (dllPath.Length == 0 && dllArg.Length > 0) dllPath = dllArg;

                    string taskNames = "";
                    if (clsid != null && _comHandlerMap!.TryGetValue(clsid, out var tasks))
                        taskNames = string.Join(", ", tasks);

                    var modules = GetLoadedDlls(pid);

                    entries.Add(new TaskHostDllEntry
                    {
                        PID = pid,
                        Handler = clsid ?? (dllArg.Length > 0 ? dllArg : "(no handler arg)"),
                        DllPath = dllPath,
                        TaskNames = taskNames,
                        ConnectionCount = connectionCounts.GetValueOrDefault(pid),
                        CommandLine = cmdLine,
                        ModuleCount = modules.Count,
                    });
                }
                catch (Exception ex)
                {
                    _logError($"TaskHostDllTracker PID {pid}: {ex.Message}");
                }
            }

            return entries.OrderByDescending(e => e.ConnectionCount).ThenBy(e => e.PID).ToList();
        }

        private static IEnumerable<int> GetTaskHostPids()
        {
            foreach (var proc in Process.GetProcessesByName("taskhostw"))
            {
                int id = proc.Id;
                proc.Dispose();
                yield return id;
            }
        }

        /// <summary>Extracts the hosted handler from a taskhostw command line: the
        /// "{CLSID}" token for COM-handler tasks, or the value after -dllname for
        /// DLL-launch tasks.</summary>
        private static string? ParseClsid(string commandLine, out string dllArg)
        {
            dllArg = "";
            if (string.IsNullOrWhiteSpace(commandLine)) return null;

            var tokens = SplitCommandLine(commandLine).Skip(1).ToList(); // drop taskhostw.exe itself
            for (int i = 0; i < tokens.Count; i++)
            {
                if (ClsidPattern.IsMatch(tokens[i])) return tokens[i];
                if (tokens[i].Equals("-dllname", StringComparison.OrdinalIgnoreCase) && i + 1 < tokens.Count)
                    dllArg = tokens[i + 1];
            }
            return null;
        }

        private static List<string> SplitCommandLine(string commandLine)
        {
            var parts = new List<string>();
            var sb = new StringBuilder();
            bool inQuotes = false;
            foreach (char c in commandLine)
            {
                if (c == '"') { inQuotes = !inQuotes; continue; }
                if (char.IsWhiteSpace(c) && !inQuotes)
                {
                    if (sb.Length > 0) { parts.Add(sb.ToString()); sb.Clear(); }
                }
                else sb.Append(c);
            }
            if (sb.Length > 0) parts.Add(sb.ToString());
            return parts;
        }

        /// <summary>CLSID → in-proc server DLL via the registry, checking HKCU, then
        /// HKLM 64-bit and 32-bit views (handlers can be registered in any of them).</summary>
        public static string? ResolveClsidDll(string clsid)
        {
            var probes = new[]
            {
                (RegistryHive.CurrentUser,  RegistryView.Default),
                (RegistryHive.LocalMachine, RegistryView.Registry64),
                (RegistryHive.LocalMachine, RegistryView.Registry32),
            };

            foreach (var (hive, view) in probes)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    foreach (string subKey in new[] { $"SOFTWARE\\Classes\\CLSID\\{clsid}\\InprocServer32",
                                                      $"SOFTWARE\\Classes\\WOW6432Node\\CLSID\\{clsid}\\InprocServer32" })
                    {
                        using var key = baseKey.OpenSubKey(subKey);
                        if (key?.GetValue(null) is string dll && !string.IsNullOrWhiteSpace(dll))
                            return Environment.ExpandEnvironmentVariables(dll.Trim('"'));
                    }
                }
                catch { }
            }
            return null;
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  Scheduled task → COM-handler CLSID map (Schedule.Service, late-bound)
        // ─────────────────────────────────────────────────────────────────────────

        private Dictionary<string, List<string>> BuildComHandlerMap()
        {
            var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
            if (type is null) return map;

            dynamic svc = Activator.CreateInstance(type)!;
            svc.Connect();
            WalkTaskFolder(svc.GetFolder("\\"), map, depth: 0);
            return map;
        }

        private void WalkTaskFolder(dynamic folder, Dictionary<string, List<string>> map, int depth)
        {
            if (depth > 6) return; // defense against pathological folder trees

            try
            {
                foreach (dynamic task in folder.GetTasks(0))
                {
                    try
                    {
                        string taskPath = (string)task.Path;
                        foreach (dynamic action in task.Definition.Actions)
                        {
                            try
                            {
                                // Only COM-handler actions expose ClassId; others throw.
                                if (action.ClassId is string clsid && ClsidPattern.IsMatch(clsid))
                                {
                                    if (!map.TryGetValue(clsid, out var list))
                                        map[clsid] = list = new List<string>();
                                    if (!list.Contains(taskPath)) list.Add(taskPath);
                                }
                            }
                            catch { /* non-COM action */ }
                        }
                    }
                    catch { /* task unreadable (permissions) */ }
                }
            }
            catch (Exception ex) { _logError($"WalkTaskFolder tasks: {ex.Message}"); }

            try
            {
                foreach (dynamic sub in folder.GetFolders(0))
                    WalkTaskFolder(sub, map, depth + 1);
            }
            catch { }
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  Command line of another process: NtQueryInformationProcess → PEB →
        //  ProcessParameters → CommandLine (x64 offsets; this app is win-x64 only).
        //  Same technique Process Explorer uses; avoids the System.Management package.
        // ─────────────────────────────────────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, ref PROCESS_BASIC_INFORMATION pbi, int cb, out int pSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public int _padding;
            public IntPtr Buffer;
        }

        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;

        public static string? GetCommandLine(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero) return null;
            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                if (NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _) != 0) return null;
                if (pbi.PebBaseAddress == IntPtr.Zero) return null;

                // x64: ProcessParameters pointer lives at PEB+0x20.
                var paramsPtr = ReadIntPtr(hProcess, pbi.PebBaseAddress + 0x20);
                if (paramsPtr == IntPtr.Zero) return null;

                // x64: CommandLine UNICODE_STRING lives at RTL_USER_PROCESS_PARAMETERS+0x70.
                var cmd = ReadStruct<UNICODE_STRING>(hProcess, paramsPtr + 0x70);
                if (cmd.Length <= 0 || cmd.Buffer == IntPtr.Zero) return null;

                var buffer = new byte[cmd.Length];
                if (!ReadProcessMemory(hProcess, cmd.Buffer, buffer, buffer.Length, out _)) return null;
                return Encoding.Unicode.GetString(buffer);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private static IntPtr ReadIntPtr(IntPtr hProcess, IntPtr address)
        {
            var buffer = new byte[IntPtr.Size];
            return ReadProcessMemory(hProcess, address, buffer, buffer.Length, out _) && IntPtr.Size == 8
                ? new IntPtr(BitConverter.ToInt64(buffer, 0))
                : IntPtr.Zero;
        }

        private static T ReadStruct<T>(IntPtr hProcess, IntPtr address) where T : struct
        {
            var buffer = new byte[Marshal.SizeOf<T>()];
            if (!ReadProcessMemory(hProcess, address, buffer, buffer.Length, out _)) return default;
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try { return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject()); }
            finally { handle.Free(); }
        }

        /// <summary>All non-exe modules loaded in the process (the DLLs actually hosted).</summary>
        public static List<string> GetLoadedDlls(int pid)
        {
            var dlls = new List<string>();
            try
            {
                using var proc = Process.GetProcessById(pid);
                foreach (ProcessModule module in proc.Modules)
                {
                    try
                    {
                        if (!module.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            dlls.Add(module.FileName);
                    }
                    catch { /* module vanished mid-enumeration */ }
                }
            }
            catch { /* process exited or protected */ }
            return dlls.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }
}
