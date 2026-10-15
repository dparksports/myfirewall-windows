using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using MyFirewall.Desktop.Models;
using MyFirewall.Desktop.Services;

namespace MyFirewall.Desktop.ViewModels
{
    public class MainViewModel : ObservableObject
    {
        private readonly NetworkMonitorService _networkMonitor;
        private readonly FirewallService _firewallService;
        private readonly DataService _dataService;
        private readonly GeoIpService _geoIpService;
        private readonly SystemSettingsService _systemSettingsService;
        private readonly ProcessBlockListService _processBlockList;
        private readonly TaskHostDllTracker _taskHostTracker;
        private readonly DispatcherTimer _timer;
        private readonly DateTime _startTime = DateTime.Now;
        private readonly Action<string> _logError;

        private Dictionary<string, BlockedIPMetadata> _blockedIPsDict = new();
        private HashSet<string> _ignoredAppsSet = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _killAppsSet = new(StringComparer.OrdinalIgnoreCase);

        // Reconciliation sweep counter (~30s at the default 2s refresh); also paces
        // the taskhostw DLL snapshot.
        private int _sweepTicks;

        // Smart-diff: keyed by ConnectionKey for in-place updates
        private readonly Dictionary<string, ConnectionInfo> _connectionMap = new();

        // Fix #10: Cache the last OS-queried connection list so that SearchFilter changes
        // apply a client-side filter without triggering expensive OS calls.
        private List<ConnectionInfo> _latestConnections = new();

        public ObservableCollection<ConnectionInfo> Connections { get; } = new();
        public ObservableCollection<BlockedIPEntry> BlockedIPs { get; } = new();
        public ObservableCollection<IgnoredAppEntry> IgnoredApps { get; } = new();
        public ObservableCollection<AlertEntry> Alerts { get; } = new();
        public ObservableCollection<TaskHostDllEntry> TaskHostDlls { get; } = new();

        private bool _isMonitorActive;
        public bool IsMonitorActive { get => _isMonitorActive; set => SetProperty(ref _isMonitorActive, value); }

        private ConnectionInfo? _selectedConnection;
        public ConnectionInfo? SelectedConnection
        {
            get => _selectedConnection;
            set
            {
                if (SetProperty(ref _selectedConnection, value))
                {
                    OnPropertyChanged(nameof(HasSelectedConnection));
                }
            }
        }

        public bool HasSelectedConnection => SelectedConnection != null;

        public bool IsConnectionDriven
        {
            get => _networkMonitor.MonitoringStrategy == ProcessMonitoringStrategy.ConnectionDriven;
            set
            {
                if (value)
                {
                    _networkMonitor.SetMonitoringStrategy(ProcessMonitoringStrategy.ConnectionDriven);
                    OnPropertyChanged(nameof(IsConnectionDriven));
                    OnPropertyChanged(nameof(IsProcessStartEtw));
                    AddAlert("Switched process monitoring to: Connection-Driven", AlertSeverity.Info);
                }
            }
        }

        public bool IsProcessStartEtw
        {
            get => _networkMonitor.MonitoringStrategy == ProcessMonitoringStrategy.ProcessStartEtw;
            set
            {
                if (value)
                {
                    _networkMonitor.SetMonitoringStrategy(ProcessMonitoringStrategy.ProcessStartEtw);
                    OnPropertyChanged(nameof(IsConnectionDriven));
                    OnPropertyChanged(nameof(IsProcessStartEtw));
                    AddAlert("Switched process monitoring to: ETW Process Start", AlertSeverity.Info);
                }
            }
        }

        private int _connectionCount;
        public int ConnectionCount { get => _connectionCount; set => SetProperty(ref _connectionCount, value); }

        private int _blockedCount;
        public int BlockedCount { get => _blockedCount; set => SetProperty(ref _blockedCount, value); }

        private string _totalUpload = "0 B";
        public string TotalUpload { get => _totalUpload; set => SetProperty(ref _totalUpload, value); }

        private string _totalDownload = "0 B";
        public string TotalDownload { get => _totalDownload; set => SetProperty(ref _totalDownload, value); }

        private string _uptimeDisplay = "00:00:00";
        public string UptimeDisplay { get => _uptimeDisplay; set => SetProperty(ref _uptimeDisplay, value); }

        private string _lastRefreshTime = "--:--:--";
        public string LastRefreshTime { get => _lastRefreshTime; set => SetProperty(ref _lastRefreshTime, value); }

        private int _refreshInterval = 2;
        public int RefreshInterval
        {
            get => _refreshInterval;
            set
            {
                if (SetProperty(ref _refreshInterval, value) && value > 0)
                {
                    _timer.Interval = TimeSpan.FromSeconds(value);
                }
            }
        }

        private int _firewallRuleCount;
        public int FirewallRuleCount { get => _firewallRuleCount; set => SetProperty(ref _firewallRuleCount, value); }

        private bool _isAdmin;
        public bool IsAdmin { get => _isAdmin; set => SetProperty(ref _isAdmin, value); }

        private string _searchFilter = "";
        public string SearchFilter
        {
            get => _searchFilter;
            set
            {
                if (SetProperty(ref _searchFilter, value))
                {
                    // Fix #10: Apply filter client-side on the cached connection list —
                    // do NOT trigger a full OS query just because the user typed a character.
                    ApplyFilterAndUpdate(_latestConnections);
                }
            }
        }

        private string _blockByNameInput = "";
        /// <summary>User-typed process name to block ("taskhostw" or "taskhostw.exe").</summary>
        public string BlockByNameInput
        {
            get => _blockByNameInput;
            set => SetProperty(ref _blockByNameInput, value);
        }

        private string _statusMessage = "Initializing...";
        public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

        public bool IsLanguageSyncEnabled
        {
            get => _systemSettingsService.IsLanguageSyncEnabled();
            set
            {
                _systemSettingsService.SetLanguageSyncEnabled(value);
                if (!value) _systemSettingsService.StopProcess("SettingSyncHost");
                _systemSettingsService.SetHardeningDefaultsEnabled(false);
                OnPropertyChanged(nameof(IsLanguageSyncEnabled));
                AddAlert($"Language Sync {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsWidgetsEnabled
        {
            get => _systemSettingsService.IsWidgetsEnabled();
            set
            {
                _systemSettingsService.SetWidgetsEnabled(value);
                if (!value) _systemSettingsService.StopProcess("Widgets");
                _systemSettingsService.SetHardeningDefaultsEnabled(false);
                OnPropertyChanged(nameof(IsWidgetsEnabled));
                AddAlert($"Windows Widgets {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsSearchHostEnabled
        {
            get => _systemSettingsService.IsSearchHostEnabled();
            set
            {
                _systemSettingsService.SetSearchHostEnabled(value);
                if (!value) _systemSettingsService.StopProcess("SearchHost");
                _systemSettingsService.SetHardeningDefaultsEnabled(false);
                OnPropertyChanged(nameof(IsSearchHostEnabled));
                AddAlert($"SearchHost Box {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsSearchHostBackgroundBingEnabled
        {
            get => !_systemSettingsService.IsSearchHostBackgroundAndBingDisabled();
            set
            {
                _systemSettingsService.SetSearchHostBackgroundAndBingDisabled(!value);
                if (!value) _systemSettingsService.StopProcess("SearchHost");
                _systemSettingsService.SetHardeningDefaultsEnabled(false);
                OnPropertyChanged(nameof(IsSearchHostBackgroundBingEnabled));
                AddAlert($"SearchHost Background & Bing Search {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsStartMenuExperienceHostEnabled
        {
            get => _systemSettingsService.IsStartMenuExperienceHostEnabled();
            set
            {
                _systemSettingsService.SetStartMenuExperienceHostEnabled(value);
                if (!value) _systemSettingsService.StopProcess("StartMenuExperienceHost");
                _systemSettingsService.SetHardeningDefaultsEnabled(false);
                OnPropertyChanged(nameof(IsStartMenuExperienceHostEnabled));
                AddAlert($"StartMenuExperienceHost {(value ? "enabled" : "removed")}", AlertSeverity.Info);
            }
        }

        public bool IsShellExperienceHostEnabled
        {
            get => _systemSettingsService.IsShellExperienceHostEnabled();
            set
            {
                _systemSettingsService.SetShellExperienceHostEnabled(value);
                if (!value) _systemSettingsService.StopProcess("ShellExperienceHost");
                _systemSettingsService.SetHardeningDefaultsEnabled(false);
                OnPropertyChanged(nameof(IsShellExperienceHostEnabled));
                AddAlert($"ShellExperienceHost {(value ? "enabled" : "removed")}", AlertSeverity.Info);
            }
        }

        public bool IsWebView2Blocked
        {
            get => _systemSettingsService.IsWebView2Blocked();
            set
            {
                _systemSettingsService.SetWebView2Blocked(value);
                if (value)
                {
                    string? path = _systemSettingsService.FindWebView2Path();
                    if (!string.IsNullOrEmpty(path))
                    {
                        _firewallService.ApplyWebView2NetworkBlock(path);
                        AddAlert($"Proactively blocked WebView2 outbound network (Path: {path})", AlertSeverity.Info);
                    }
                    else
                    {
                        AddAlert("Failed to locate msedgewebview2.exe on this system.", AlertSeverity.Warning);
                    }
                }
                else
                {
                    _firewallService.RemoveWebView2NetworkBlock();
                    AddAlert("Allowed WebView2 outbound network requests.", AlertSeverity.Info);
                }
                OnPropertyChanged(nameof(IsWebView2Blocked));
            }
        }

        public bool IsTelemetryEnabled
        {
            get => TelemetryService.IsTelemetryEnabled;
            set
            {
                TelemetryService.IsTelemetryEnabled = value;
                OnPropertyChanged(nameof(IsTelemetryEnabled));
                if (value) AddAlert("App telemetry data collection enabled.", AlertSeverity.Info);
                else AddAlert("App telemetry data collection disabled.", AlertSeverity.Warning);
            }
        }

        // Commands
        public RelayCommand<object> BlockIPCommand { get; }
        public RelayCommand<object> BlockProcessCommand { get; }
        public RelayCommand BlockByNameCommand { get; }
        public RelayCommand<string> UnblockIPCommand { get; }
        public RelayCommand<string> IgnoreAppCommand { get; }
        public RelayCommand<string> UnignoreAppCommand { get; }
        public RelayCommand<object> StopAppCommand { get; }
        public RelayCommand ClearAlertsCommand { get; }
        public RelayCommand RefreshCommand { get; }
        public RelayCommand ExportLogCommand { get; }
        public RelayCommand DeselectConnectionCommand { get; }

        public MainViewModel()
        {
            // Fix #8: Use DataService.ResolveBaseDir() indirectly — the DataService now
            // computes the correct path. Crash log uses the same resolved directory.
            string? exeDir = Path.GetDirectoryName(Environment.ProcessPath
                             ?? Process.GetCurrentProcess().MainModule?.FileName);
            string logDir  = string.IsNullOrEmpty(exeDir) ? AppContext.BaseDirectory : exeDir;

            // Walk up from bin/Debug/net8.0-windows/ if we're in a build output dir
            string candidate = Path.GetFullPath(Path.Combine(logDir, "..", "..", "..", ".."));
            if (Directory.Exists(candidate)) logDir = candidate;

            Action<string> logError = msg =>
            {
                try { File.AppendAllText(Path.Combine(logDir, "crash.log"), $"[{DateTime.Now:s}] {msg}\n"); }
                catch { /* swallow if we can't even write the crash log */ }
            };
            _logError = logError;

            _geoIpService         = new GeoIpService();
            _dataService          = new DataService(logError);
            _firewallService      = new FirewallService(logError);
            _systemSettingsService= new SystemSettingsService(logError);
            _networkMonitor       = new NetworkMonitorService(logError, _geoIpService);
            _processBlockList     = new ProcessBlockListService(_firewallService, logError);
            _taskHostTracker      = new TaskHostDllTracker(logError);

            _networkMonitor.OnProactiveAlert = alert =>
            {
                Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                {
                    AddAlertEntry(alert);
                }));
            };

            // Real-time enforcement: a blocked process touching a new destination is
            // firewall-blocked the moment the ETW event arrives (milliseconds, not one
            // refresh interval), including UDP and send-and-die beacons.
            _networkMonitor.IsBlockedProcess = name => _blockedProcessNames.Contains(name);
            _networkMonitor.OnAppRuleEnsured = (name, path) => _processBlockList.RegisterPath(
                ProcessBlockListService.NormalizeName(name), path);
            _networkMonitor.OnBlockedEndpointObserved = (remoteIp, name, pid, isUdp) =>
            {
                Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        if (string.IsNullOrEmpty(remoteIp) || _blockedIPsDict.ContainsKey(remoteIp)) return;
                        if (!_firewallService.AddBlockRule(remoteIp, name)) return;

                        _blockedIPsDict[remoteIp] = new BlockedIPMetadata { Application = name, Timestamp = DateTime.Now };
                        _dataService.SaveBlocked(_blockedIPsDict);
                        _networkMonitor.ResetConnectionsToIp(remoteIp);
                        SyncObservables();
                        AddAlert($"Event-block{(isUdp ? " (UDP)" : "")}: {name} → {remoteIp}", AlertSeverity.Warning);
                    }
                    catch (Exception ex)
                    {
                        AddAlert($"Event enforcement failed for {remoteIp}: {ex.Message}", AlertSeverity.Critical);
                    }
                }));
            };

            // Block-by-name watcher: when a blocked process name starts at a path we
            // have not ruled yet (new copy, other arch dir), convert the kernel image
            // path and add a firewall rule for that location immediately.
            _networkMonitor.OnBlockedProcessStart = (ntImagePath, bareName, pid) =>
            {
                Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        string name = ProcessBlockListService.NormalizeName(bareName);
                        string dosPath = ProcessBlockListService.NtToDosPath(ntImagePath) ?? ntImagePath;
                        if (!_processBlockList.RegisterPath(name, dosPath)) return;

                        string dictKey = _blockedIPsDict.Keys.FirstOrDefault(
                            k => k.Equals(name, StringComparison.OrdinalIgnoreCase)) ?? name;
                        if (_blockedIPsDict.TryGetValue(dictKey, out var meta))
                        {
                            _blockedIPsDict[dictKey] = new BlockedIPMetadata
                            {
                                Application = string.Join(";", _processBlockList.GetKnownPaths(name)),
                                Timestamp = meta.Timestamp
                            };
                            _dataService.SaveBlocked(_blockedIPsDict);
                        }
                        SyncObservables();
                        AddAlert($"Watch: {name} appeared at a new location (PID {pid}) — blocked {dosPath}", AlertSeverity.Warning);
                    }
                    catch (Exception ex)
                    {
                        AddAlert($"Block watcher failed for {bareName}: {ex.Message}", AlertSeverity.Critical);
                    }
                }));
            };

            // Fix: StopAppCommand uses object parameter so WPF string→int conversion isn't needed
            BlockIPCommand         = new RelayCommand<object>(ExecuteBlockIP);
            BlockProcessCommand    = new RelayCommand<object>(ExecuteBlockProcess);
            BlockByNameCommand     = new RelayCommand(_ => ExecuteBlockByName());
            UnblockIPCommand       = new RelayCommand<string>(ExecuteUnblockIP);
            IgnoreAppCommand       = new RelayCommand<string>(ExecuteIgnoreApp);
            UnignoreAppCommand     = new RelayCommand<string>(ExecuteUnignoreApp);
            StopAppCommand         = new RelayCommand<object>(ExecuteStopApp);
            ClearAlertsCommand     = new RelayCommand(_ => Alerts.Clear());
            RefreshCommand         = new RelayCommand(_ => Timer_Tick(null, EventArgs.Empty));
            ExportLogCommand       = new RelayCommand(_ => ExecuteExportLog());
            DeselectConnectionCommand = new RelayCommand(_ => SelectedConnection = null);

            // Check admin status
            IsAdmin = CheckIsAdmin();

            LoadData();

            // Proactive WebView2 Network Block on Startup
            try
            {
                if (_systemSettingsService.IsWebView2Blocked())
                {
                    string? path = _systemSettingsService.FindWebView2Path();
                    if (!string.IsNullOrEmpty(path))
                    {
                        _firewallService.ApplyWebView2NetworkBlock(path);
                    }
                }
            }
            catch { }

            // Apply hardening defaults (language sync, widgets, SearchHost, StartMenu/Shell
            // hosts disabled) + the kill list, then firewall-block default-blocked processes.
            ApplyStartupHardening();
            ApplyDefaultProcessFirewallBlocks();

            try
            {
                _networkMonitor.Start();
                StatusMessage = "Network monitor active";
            }
            catch (Exception ex)
            {
                StatusMessage = $"ETW failed: {ex.Message}";
                AddAlert($"Failed to start network monitor: {ex.Message}", AlertSeverity.Critical);
            }

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(_refreshInterval) };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            // First taskhostw DLL snapshot off the UI thread (the COM task-folder walk
            // can take a second on first run); the sweep keeps it fresh afterwards.
            System.Threading.Tasks.Task.Run(() =>
            {
                try { RefreshTaskHostDlls(); }
                catch (Exception ex) { _logError($"Initial taskhost snapshot: {ex.Message}"); }
            });
        }

        /// <summary>
        /// Rebuilds the taskhostw panel: one entry per live instance, with the hosted
        /// handler CLSID resolved to its DLL and the owning scheduled task(s).
        /// Safe off the UI thread — marshals the collection update via the dispatcher.
        /// </summary>
        private void RefreshTaskHostDlls()
        {
            var snapshot = _taskHostTracker.Snapshot(_latestConnections);
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                TaskHostDlls.Clear();
                foreach (var entry in snapshot) TaskHostDlls.Add(entry);
            }));
        }

        private static bool CheckIsAdmin()
        {
            try
            {
                var identity  = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private void LoadData()
        {
            var data = _dataService.LoadData();
            _blockedIPsDict = data.BlockedIPs;
            _ignoredAppsSet = data.IgnoredApps;
            _killAppsSet    = _dataService.LoadKillList();

            // Adopt the built-in default policy (current block list, default process
            // blocks, default kill list). Explicit user opt-outs are never re-added.
            var removedDefaults = _dataService.LoadRemovedDefaults();
            _dataService.SeedDefaults(_blockedIPsDict, _killAppsSet, removedDefaults);
            _dataService.SaveBlocked(_blockedIPsDict);
            _dataService.SaveKillList(_killAppsSet);

            SyncObservables();
        }

        /// <summary>
        /// Applies the startup hardening defaults (language sync, widgets, SearchHost box,
        /// SearchHost background &amp; Bing search, StartMenuExperienceHost, ShellExperienceHost
        /// — all disabled) and the default kill list, unless the user has manually taken
        /// control of any toggle (opt-out recorded in the master switch).
        /// </summary>
        private void ApplyStartupHardening()
        {
            try
            {
                if (!_systemSettingsService.IsHardeningDefaultsEnabled()) return;

                _systemSettingsService.ApplyHardeningDefaults(_killAppsSet);
                AddAlert("Hardening defaults applied: language sync, widgets, SearchHost box/background & Bing, StartMenuExperienceHost and ShellExperienceHost disabled.", AlertSeverity.Info);
            }
            catch (Exception ex)
            {
                _logError($"ApplyStartupHardening: {ex.Message}");
            }
        }

        /// <summary>
        /// Applies app-level firewall rules for every blocked process name, whether it
        /// arrived from defaults (MpCmdRun / MsMpEng / …) or the user's own block-by-name
        /// entries. For each name: seed the known-path set from persisted state, resolve
        /// every current location (running instances + standard system dirs), and rule
        /// them all — so a not-yet-running binary like taskhostw.exe is still blocked
        /// before its first connection. Names with no resolvable path stay registered:
        /// the ETW process-start watcher firewalls them the moment they appear.
        /// </summary>
        private void ApplyDefaultProcessFirewallBlocks()
        {
            bool dirty = false;
            foreach (var procName in _blockedProcessNames.ToList())
            {
                try
                {
                    if (_blockedIPsDict.TryGetValue(procName, out var existing))
                        _processBlockList.SeedKnownPaths(procName, ParseStoredPaths(existing.Application));

                    var paths = _processBlockList.BlockByName(procName);
                    if (paths.Count == 0) continue;

                    if (_blockedIPsDict.TryGetValue(procName, out var meta))
                    {
                        _blockedIPsDict[procName] = new BlockedIPMetadata
                        {
                            Application = string.Join(";", _processBlockList.GetKnownPaths(procName)),
                            Timestamp = meta.Timestamp
                        };
                        dirty = true;
                    }
                    AddAlert($"Startup block: {procName} — {paths.Count} location(s) ruled.", AlertSeverity.Warning);
                }
                catch (Exception ex)
                {
                    _logError($"ApplyDefaultProcessFirewallBlocks [{procName}]: {ex.Message}");
                }
            }
            if (dirty) _dataService.SaveBlocked(_blockedIPsDict);
        }

        /// <summary>Parses the ';'-joined path set persisted in a blocked.txt process entry.</summary>
        private static List<string> ParseStoredPaths(string stored) =>
            stored.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                  .Where(p => p.Contains('\\'))
                  .ToList();

        private void RebuildBlockedProcessNames()
        {
            _blockedProcessNames.Clear();
            // Note: We no longer auto-populate process names from _blockedIPs to avoid
            // aggressive kill-loops for shared components like WebView2.
            // Process name blocking is now an explicit, separate action if added in the future.
            foreach (var kvp in _blockedIPsDict)
            {
                if (!IPAddress.TryParse(kvp.Key, out _))
                    _blockedProcessNames.Add(kvp.Key); // treat non-IP key as process name
            }
        }

        private void SyncObservables()
        {
            RebuildBlockedProcessNames();

            BlockedIPs.Clear();
            foreach (var kvp in _blockedIPsDict.OrderBy(x => x.Key))
            {
                string display = kvp.Value.Application;
                if (!IPAddress.TryParse(kvp.Key, out _))
                {
                    // Process-name entry: the raw field is the persisted path set —
                    // show "N path(s) blocked" instead of the raw ';'-joined blob.
                    int pathCount = ParseStoredPaths(kvp.Value.Application).Count;
                    display = pathCount > 0
                        ? $"{pathCount} path(s) blocked"
                        : (kvp.Value.Application.Contains('\\') ? kvp.Value.Application : "watching for first appearance");
                }
                BlockedIPs.Add(new BlockedIPEntry { IP = kvp.Key, Application = display, Timestamp = kvp.Value.Timestamp });
            }

            BlockedCount = BlockedIPs.Count;

            IgnoredApps.Clear();
            foreach (var app in _ignoredAppsSet.OrderBy(x => x))
                IgnoredApps.Add(new IgnoredAppEntry { Application = app });

            // Refresh firewall rule count (cached — no expensive COM enumeration unless invalidated)
            try { FirewallRuleCount = _firewallService.GetRuleCount(); }
            catch { /* non-critical */ }
        }

        /// <summary>
        /// Re-asserts app-level rules for every blocked process at every known path;
        /// AddBlockProcessRule checks rule existence internally, so this only repairs drift.
        /// </summary>
        private void ReassertAppRules()
        {
            foreach (string name in _processBlockList.RegisteredNames.ToList())
            {
                foreach (string path in _processBlockList.GetKnownPaths(name))
                {
                    try { _firewallService.AddBlockProcessRule(name, path); }
                    catch { /* non-critical — retried next sweep */ }
                }
            }
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            IsMonitorActive = _networkMonitor.IsRunning;

            // Update uptime
            UptimeDisplay  = (DateTime.Now - _startTime).ToString(@"hh\:mm\:ss");
            LastRefreshTime = DateTime.Now.ToString("HH:mm:ss");

            // Update total traffic stats
            var traffic = _networkMonitor.GetTotalTrafficStats();
            TotalUpload   = FormatBytes(traffic.TotalSent);
            TotalDownload = FormatBytes(traffic.TotalReceived);

            // Query OS for fresh connections
            var freshConns = _networkMonitor.GetConnections(_ignoredAppsSet, _blockedIPsDict, _blockedProcessNames);

            // Fix #10: Store the unfiltered OS result so SearchFilter can apply client-side.
            _latestConnections = freshConns;

            var alerts = _networkMonitor.AutoEnforce(freshConns, _firewallService, _blockedIPsDict, _blockedProcessNames);

            bool saveNeeded = false;
            foreach (var alert in alerts)
            {
                AddAlertEntry(alert);
                saveNeeded = true;
            }

            if (saveNeeded)
            {
                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
            }

            // Reconciliation sweep (~30s at the default 2s refresh): re-apply
            // app-level rules that were deleted by other tools or policy refresh,
            // and refresh the taskhostw DLL snapshot.
            if (++_sweepTicks >= 15)
            {
                _sweepTicks = 0;
                ReassertAppRules();
                RefreshTaskHostDlls();
            }

            // Apply filter (client-side) and smart-diff update
            ApplyFilterAndUpdate(freshConns);
            ConnectionCount = Connections.Count;
        }

        /// <summary>
        /// Fix #10: Applies the current search filter to a connection list (client-side),
        /// then drives the smart-diff update. Called from Timer_Tick AND from SearchFilter setter.
        /// </summary>
        private void ApplyFilterAndUpdate(List<ConnectionInfo> source)
        {
            IEnumerable<ConnectionInfo> filtered = source;

            if (!string.IsNullOrWhiteSpace(_searchFilter))
            {
                string filter = _searchFilter.ToLower();
                filtered = source.Where(c =>
                    c.ApplicationName.ToLower().Contains(filter) ||
                    c.Destination.Contains(filter) ||
                    c.Domain.ToLower().Contains(filter) ||
                    c.Location.ToLower().Contains(filter)
                );
            }

            SmartUpdateConnections(filtered.ToList());
            ConnectionCount = Connections.Count;
        }

        /// <summary>
        /// Smart-diff connection list: update in-place, add new, remove stale.
        /// This eliminates DataGrid flicker from Clear() + re-add.
        /// </summary>
        private void SmartUpdateConnections(List<ConnectionInfo> newConns)
        {
            var newKeys = new HashSet<string>();

            foreach (var conn in newConns)
            {
                newKeys.Add(conn.ConnectionKey);

                if (_connectionMap.TryGetValue(conn.ConnectionKey, out var existing))
                {
                    // Update existing entry's mutable fields in-place
                    int idx = Connections.IndexOf(existing);
                    if (idx >= 0)
                    {
                        Connections[idx] = conn;
                        _connectionMap[conn.ConnectionKey] = conn;

                        // If this was the selected connection, update the selection reference to the new instance
                        // so the details panel updates in real-time with the latest bytes and durations.
                        if (SelectedConnection != null && SelectedConnection.ConnectionKey == conn.ConnectionKey)
                        {
                            SelectedConnection = conn;
                        }
                    }
                }
                else
                {
                    // New connection
                    Connections.Add(conn);
                    _connectionMap[conn.ConnectionKey] = conn;
                }
            }

            // Remove connections no longer present
            var staleKeys = _connectionMap.Keys.Except(newKeys).ToList();
            foreach (var key in staleKeys)
            {
                if (_connectionMap.TryGetValue(key, out var stale))
                {
                    Connections.Remove(stale);
                    _connectionMap.Remove(key);

                    if (SelectedConnection != null && SelectedConnection.ConnectionKey == key)
                    {
                        SelectedConnection = null;
                    }
                }
            }
        }

        /// <summary>
        /// Fix: Block command now correctly receives ConnectionInfo or "IP|AppName" string.
        /// </summary>
        private void ExecuteBlockIP(object? parameter)
        {
            if (parameter == null) return;

            string ip  = "";
            string app = "Unknown";

            if (parameter is ConnectionInfo conn)
            {
                ip  = conn.Destination;
                app = conn.ApplicationName;
            }
            else if (parameter is string ipAndApp)
            {
                if (string.IsNullOrWhiteSpace(ipAndApp)) return;
                var parts = ipAndApp.Split('|');
                ip  = parts[0].Trim();
                app = parts.Length > 1 ? parts[1].Trim() : "Unknown";
            }
            else
            {
                return;
            }

            if (!IPAddress.TryParse(ip, out _)) return;

            if (!_blockedIPsDict.ContainsKey(ip))
            {
                if (_firewallService.AddBlockRule(ip, app))
                {
                    _blockedIPsDict[ip] = new BlockedIPMetadata { Application = app, Timestamp = DateTime.Now };
                    _dataService.SaveBlocked(_blockedIPsDict);
                    _networkMonitor.ResetConnectionsToIp(ip); // Sever any existing active connections
                    SyncObservables();
                    AddAlert($"Blocked {ip} ({app})", AlertSeverity.Warning);
                }
                else
                {
                    AddAlert($"Failed to block {ip}. Ensure app is running as Administrator.", AlertSeverity.Critical);
                }
            }
        }

        private void ExecuteBlockProcess(object? parameter)
        {
            if (parameter is not ConnectionInfo conn) return;

            string app = conn.ApplicationName;
            if (string.IsNullOrWhiteSpace(app) || app == "Unknown" || app == "Idle")
            {
                AddAlert("Cannot block application: name unknown.", AlertSeverity.Warning);
                return;
            }
            if (IPAddress.TryParse(app, out _)) return;

            BlockProcessName(app, hintPath: conn.ExecutablePath);
        }

        /// <summary>
        /// Blocks a process BY NAME (e.g. "taskhostw.exe"), not just the one path a
        /// live connection happened to use: resolves every location the name exists at
        /// (running instances + standard system dirs), rules them all, and registers
        /// the name with the ETW process-start watcher for paths not present yet.
        /// </summary>
        private void ExecuteBlockByName()
        {
            string raw = (BlockByNameInput ?? "").Trim();
            BlockByNameInput = "";
            if (raw.Length == 0) return;

            if (IPAddress.TryParse(raw, out _))
            {
                AddAlert("That looks like an IP address — right-click a connection to block it.", AlertSeverity.Warning);
                return;
            }

            BlockProcessName(raw, hintPath: null);
        }

        private void BlockProcessName(string rawName, string? hintPath)
        {
            string name = ProcessBlockListService.NormalizeName(rawName);
            if (name.Length == 0) return;

            if (_blockedIPsDict.Keys.Any(k => k.Equals(name, StringComparison.OrdinalIgnoreCase)))
            {
                AddAlert($"{name} is already blocked.", AlertSeverity.Info);
                return;
            }

            // A hint path from a live connection counts as a known location even when
            // the resolver cannot see the instance anymore (process exited mid-block).
            if (!string.IsNullOrWhiteSpace(hintPath) && hintPath != "N/A" && File.Exists(hintPath))
                _processBlockList.SeedKnownPaths(name, new[] { hintPath });

            var paths = _processBlockList.BlockByName(name);

            _blockedIPsDict[name] = new BlockedIPMetadata
            {
                Application = paths.Count > 0
                    ? string.Join(";", _processBlockList.GetKnownPaths(name))
                    : "watching — no copy found yet",
                Timestamp = DateTime.Now
            };
            _dataService.SaveBlocked(_blockedIPsDict);
            SyncObservables();
            Timer_Tick(null, EventArgs.Empty);

            if (paths.Count > 0)
                AddAlert($"Blocked {name} at {paths.Count} location(s): {string.Join(", ", paths)}", AlertSeverity.Warning);
            else
                AddAlert($"Blocked {name} by name — no copy found yet; the watcher will firewall it the moment it appears.", AlertSeverity.Warning);
        }

        private void ExecuteUnblockIP(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;

            if (_blockedIPsDict.Remove(ip))
            {
                if (System.Net.IPAddress.TryParse(ip, out _))
                    _firewallService.RemoveBlockRule(ip);
                else
                {
                    // Process-name entry: drop every path's rule pair and forget the
                    // name so the process-start watcher stops watching it.
                    _firewallService.RemoveBlockProcessRule(ip);
                    _processBlockList.Forget(ProcessBlockListService.NormalizeName(ip));
                }

                // Remember explicit opt-outs so startup seeding never re-adds a default entry.
                if (DefaultPolicy.IsDefaultBlockedKey(ip))
                {
                    var removed = _dataService.LoadRemovedDefaults();
                    if (removed.Add(DefaultPolicy.BlockKey(ip)))
                        _dataService.SaveRemovedDefaults(removed);
                }

                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
                AddAlert($"Unblocked {ip}", AlertSeverity.Info);
            }
        }

        private void ExecuteIgnoreApp(string? app)
        {
            if (string.IsNullOrWhiteSpace(app)) return;
            app = app.ToLower();

            if (_ignoredAppsSet.Add(app))
            {
                _dataService.SaveIgnored(_ignoredAppsSet);
                SyncObservables();
                AddAlert($"Now ignoring {app}", AlertSeverity.Info);
            }
        }

        private void ExecuteUnignoreApp(string? app)
        {
            if (string.IsNullOrWhiteSpace(app)) return;
            app = app.ToLower();

            if (_ignoredAppsSet.Remove(app))
            {
                _dataService.SaveIgnored(_ignoredAppsSet);
                SyncObservables();
                AddAlert($"Restored {app}", AlertSeverity.Info);
            }
        }

        /// <summary>
        /// Fix: StopAppCommand now accepts object and handles string-to-int conversion explicitly.
        /// WPF passes CommandParameter as string even when binding to an int property.
        /// </summary>
        private void ExecuteStopApp(object? parameter)
        {
            int pid;
            if (parameter is int i) pid = i;
            else if (parameter is string s && int.TryParse(s, out int parsed)) pid = parsed;
            else
            {
                AddAlert("Failed to stop process: invalid PID", AlertSeverity.Critical);
                return;
            }

            try
            {
                var process = Process.GetProcessById(pid);
                string name = process.ProcessName;
                process.Kill(entireProcessTree: true); // Kill tree for more effective termination
                AddAlert($"Stopped {name} and its children (PID {pid})", AlertSeverity.Warning);
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5) // Access Denied
            {
                AddAlert($"Access denied to stop PID {pid}. System or protected process?", AlertSeverity.Critical);
            }
            catch (Exception ex)
            {
                AddAlert($"Failed to stop PID {pid}: {ex.Message}", AlertSeverity.Critical);
            }
        }

        private void ExecuteExportLog()
        {
            try
            {
                var alertMessages = Alerts.Select(a => $"[{a.Timestamp}] {a.Message}");
                string path = _dataService.ExportReport(_blockedIPsDict, _ignoredAppsSet, alertMessages);
                if (!string.IsNullOrEmpty(path))
                {
                    AddAlert($"Report exported to {Path.GetFileName(path)}", AlertSeverity.Info);
                    // Open the report file
                    Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
                }
            }
            catch (Exception ex)
            {
                AddAlert($"Export failed: {ex.Message}", AlertSeverity.Critical);
            }
        }

        private void AddAlert(string message, AlertSeverity severity)
        {
            AddAlertEntry(new AlertEntry { Message = message, Severity = severity });
        }

        private void AddAlertEntry(AlertEntry alert)
        {
            Alerts.Insert(0, alert); // newest first
            while (Alerts.Count > 20) Alerts.RemoveAt(Alerts.Count - 1);
        }

        public void Shutdown()
        {
            // Stop the timer to prevent post-disposal tick events
            _timer.Stop();
            _timer.Tick -= Timer_Tick;
            _networkMonitor.Stop();
            _dataService.SaveBlocked(_blockedIPsDict);
            _dataService.SaveIgnored(_ignoredAppsSet);
            // Fix #15: Dispose GeoIpService (and its HttpClient) on shutdown
            _geoIpService.Dispose();
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
