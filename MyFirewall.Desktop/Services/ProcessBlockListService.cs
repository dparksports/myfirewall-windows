using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace MyFirewall.Desktop.Services
{
    /// <summary>
    /// Translates "block this process by name" into firewall reality.
    ///
    /// Windows Firewall rules cannot match a bare image name — INetFwRule.ApplicationName
    /// requires an absolute path, with no wildcards. So blocking by name means:
    ///   1. resolve every path the name currently exists at (running instances +
    ///      standard system directories),
    ///   2. add one block rule per path (FirewallService.AddBlockProcessRule),
    ///   3. keep watching: when the same name shows up at a NEW path (ETW process
    ///      start), register it and add a rule for it too.
    ///
    /// Known limitation, surfaced deliberately rather than papered over: path-keyed
    /// rules do not follow a copy of the binary under a different name — that is a
    /// property of Windows Firewall itself, not of this resolver.
    /// </summary>
    public class ProcessBlockListService
    {
        private readonly FirewallService _firewall;
        private readonly Action<string> _logError;

        // name (bare, no .exe) → every path we have ever blocked for that name.
        // Persisted by the caller as the Application field of blocked.txt (joined ';').
        private readonly Dictionary<string, HashSet<string>> _knownPaths = new(StringComparer.OrdinalIgnoreCase);

        public ProcessBlockListService(FirewallService firewall, Action<string> logError)
        {
            _firewall = firewall;
            _logError = logError;
        }

        /// <summary>Normalizes user input ("taskhostw", "taskhostw.exe", "TASKHOSTW.EXE")
        /// to the bare, lower-cased name used everywhere else (blocked.txt keys,
        /// Process.ProcessName comparisons).</summary>
        public static string NormalizeName(string input)
        {
            string name = input.Trim();
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
            return name.ToLowerInvariant();
        }

        /// <summary>All paths the given name can currently be found at: live instances
        /// first, then standard system directories (System32 / SysWOW64 / Windows) so a
        /// not-currently-running system binary still gets blocked before it starts.</summary>
        public List<string> ResolvePaths(string bareName)
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in Process.GetProcessesByName(bareName))
            {
                try
                {
                    string? path = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) && File.Exists(path)) paths.Add(path);
                }
                catch { /* protected / other-session process — standard-dir probe below */ }
                finally { proc.Dispose(); }
            }

            string exe = bareName + ".exe";
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var probeDirs = new[]
            {
                Environment.SystemDirectory,
                Path.Combine(windir, "SysWOW64"),
                windir,
            }.Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var dir in probeDirs)
            {
                try
                {
                    string candidate = Path.Combine(dir, exe);
                    if (File.Exists(candidate)) paths.Add(candidate);
                }
                catch (Exception ex) { _logError($"ResolvePaths probe {dir}: {ex.Message}"); }
            }

            return paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Blocks a process by name: resolves every current path and adds an
        /// app-level firewall rule for each. Returns the paths blocked (possibly empty —
        /// the name is still registered so the process-start watcher catches it later).</summary>
        public List<string> BlockByName(string bareName)
        {
            var blocked = new List<string>();
            foreach (string path in ResolvePaths(bareName))
            {
                if (_firewall.AddBlockProcessRule(bareName, path))
                {
                    RegisterPath(bareName, path);
                    blocked.Add(path);
                }
            }
            return blocked;
        }

        /// <summary>Records a path as known for a name (dedups the watcher).
        /// Returns true when the path is NEW for this name (rule was just applied).</summary>
        public bool RegisterPath(string bareName, string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path == "N/A") return false;

            if (!_knownPaths.TryGetValue(bareName, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _knownPaths[bareName] = set;
            }
            if (!set.Add(path)) return false; // already known

            _firewall.AddBlockProcessRule(bareName, path);
            return true;
        }

        /// <summary>Seeds the known-path set from persisted state without re-adding
        /// rules (used at startup before reconciliation runs).</summary>
        public void SeedKnownPaths(string bareName, IEnumerable<string> paths)
        {
            if (!_knownPaths.TryGetValue(bareName, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _knownPaths[bareName] = set;
            }
            foreach (string p in paths) set.Add(p);
        }

        public IReadOnlyList<string> GetKnownPaths(string bareName)
            => _knownPaths.TryGetValue(bareName, out var set)
                ? set.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList()
                : Array.Empty<string>();

        /// <summary>Every process name the watcher currently tracks (drives the
        /// reconciliation sweep that repairs drifted/deleted firewall rules).</summary>
        public IEnumerable<string> RegisteredNames => _knownPaths.Keys;

        public void Forget(string bareName) => _knownPaths.Remove(bareName);

        // ─────────────────────────────────────────────────────────────────────────
        //  NT device path → DOS path conversion (ETW reports image paths as
        //  \Device\HarddiskVolume4\Windows\System32\taskhostw.exe)
        // ─────────────────────────────────────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        /// <summary>Converts an NT kernel path (\Device\HarddiskVolumeN\…) to a drive
        /// letter path (C:\…). Returns null when no mapping matches.</summary>
        public static string? NtToDosPath(string ntPath)
        {
            if (string.IsNullOrEmpty(ntPath) || !ntPath.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
                return null;

            try
            {
                var sb = new StringBuilder(512);
                for (char drive = 'A'; drive <= 'Z'; drive++)
                {
                    sb.Clear();
                    if (QueryDosDevice(drive + ":", sb, sb.Capacity) == 0) continue;
                    string device = sb.ToString();
                    if (!string.IsNullOrEmpty(device) &&
                        ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                    {
                        return drive + ":\\" + ntPath[device.Length..].TrimStart('\\');
                    }
                }
            }
            catch { }
            return null;
        }
    }
}
