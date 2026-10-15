using System;
using System.Collections.Generic;

namespace MyFirewall.Desktop.Services
{
    /// <summary>
    /// Manages Windows Firewall rules via the HNetCfg.FwPolicy2 COM API.
    /// Uses dynamic dispatch for all COM calls to avoid .NET 8 vtable marshalling regressions.
    /// Fix #5: RuleExists check is inlined inside AddBlockRule's lock to prevent TOCTOU races.
    /// Fix #7: FirewallRuleCount is cached and only re-queried when rules change.
    /// Fix #A: Removed duplicate constant definitions; use ComInterop.cs enums throughout.
    /// </summary>
    public class FirewallService
    {
        private const string FirewallRulePrefix = "TCP-Monitor-Block";

        private readonly object _fwLock = new();
        private readonly Action<string> _logError;

        // Fix #7: Cached rule count — avoids enumerating all WFP rules every 2 seconds.
        private int _cachedRuleCount = -1;

        public FirewallService(Action<string> logError)
        {
            _logError = logError;
        }

        private INetFwPolicy2? GetPolicy()
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            return type is null ? null : (INetFwPolicy2)Activator.CreateInstance(type)!;
        }

        /// <summary>
        /// Fix #5: Private non-locking variant used only inside an existing lock scope.
        /// Callers must hold _fwLock before calling this.
        /// </summary>
        private bool RuleExistsUnsafe(INetFwPolicy2 policy, string ip, string processName)
        {
            string expectedName = $"{FirewallRulePrefix}-{processName}-{ip}";
            try
            {
                foreach (INetFwRule r in policy.Rules)
                {
                    try
                    {
                        if (r.Name == expectedName) return true;
                        
                        string remoteIp = r.RemoteAddresses;
                        if (remoteIp != null && r.Name.StartsWith(FirewallRulePrefix) && (remoteIp == ip || remoteIp.StartsWith(ip + "/")))
                            return true;
                    }
                    catch { /* skip rules we can't read */ }
                }
            }
            catch (Exception ex) { _logError($"FirewallService.RuleExistsUnsafe: {ex.Message}"); }
            return false;
        }

        /// <summary>
        /// Public rule-existence check (acquires its own lock).
        /// </summary>
        public bool RuleExists(string ip, string processName)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;
                    return RuleExistsUnsafe(policy, ip, processName);
                }
                catch (Exception ex) { _logError($"FirewallService.RuleExists: {ex.Message}"); }
                return false;
            }
        }

        public bool AddBlockRule(string ip, string processName)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;

            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) { _logError("FirewallService: Could not acquire HNetCfg.FwPolicy2"); return false; }

                    // Fix #5: Check existence inside the lock — no window between check and add.
                    if (RuleExistsUnsafe(policy, ip, processName)) return true;

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;

                    // ROOT CAUSE FIX: Windows Firewall COM API throws E_INVALIDARG
                    // ("Value does not fall within the expected range") when Protocol=ANY(256)
                    // is combined with a specific RemoteAddresses value. The fix is to create
                    // separate TCP and UDP outbound block rules for the target IP, which the
                    // API accepts without error.
                    AddRuleForProtocol(policy, ruleType, ip, processName,
                        NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT);
                    AddRuleForProtocol(policy, ruleType, ip, processName,
                        NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT);
                    AddRuleForProtocol(policy, ruleType, ip, processName,
                        NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN);
                    AddRuleForProtocol(policy, ruleType, ip, processName,
                        NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN);

                    // Fix #7: Invalidate cache after a successful add.
                    _cachedRuleCount = -1;
                    return true;
                }
                catch (Exception ex)
                {
                    _logError($"FirewallService.AddBlockRule({ip}): {ex.Message}");
                    return false;
                }
            }
        }

        private static void AddRuleForProtocol(
            INetFwPolicy2 policy,
            Type ruleType,
            string ip,
            string processName,
            NET_FW_IP_PROTOCOL protocol,
            NET_FW_RULE_DIRECTION direction)
        {
            string protoTag = protocol == NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_TCP ? "TCP" : "UDP";
            string dirTag   = direction == NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT ? "OUT" : "IN";
            string name     = $"{FirewallRulePrefix}-{processName}-{ip}-{protoTag}-{dirTag}";

            // Avoid adding a duplicate rule.
            try { if (policy.Rules.Item(name) != null) return; } catch { }

            dynamic rule = Activator.CreateInstance(ruleType)!;
            rule.Name            = name;
            // FIXED: The Windows Firewall API throws E_INVALIDARG on Add() if Description contains '|'
            rule.Description     = $"Auto-blocked by TCP Monitor, application={processName}, {protoTag} {dirTag}";
            rule.Protocol        = (int)protocol;
            rule.RemoteAddresses = ip;
            rule.Direction       = (int)direction;
            rule.Action          = (int)NET_FW_ACTION.NET_FW_ACTION_BLOCK;
            rule.Enabled         = true;
            rule.Profiles        = 7;

            dynamic dynPolicy = policy;
            dynPolicy.Rules.Add(rule);
        }

        public void RemoveBlockRule(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;

                    var toRemove = new List<string>();
                    foreach (INetFwRule r in policy.Rules)
                    {
                        try
                        {
                            string remoteIp = r.RemoteAddresses;
                            if (r.Name.StartsWith(FirewallRulePrefix) && remoteIp != null && (remoteIp == ip || remoteIp.StartsWith(ip + "/")))
                                toRemove.Add(r.Name);
                        }
                        catch { }
                    }

                    foreach (var name in toRemove)
                        policy.Rules.Remove(name);

                    // Fix #7: Invalidate cache after removal.
                    if (toRemove.Count > 0) _cachedRuleCount = -1;
                }
                catch (Exception ex) { _logError($"FirewallService.RemoveBlockRule({ip}): {ex.Message}"); }
            }
        }

        /// <summary>
        /// Fix #7: Returns a cached count of TCP-Monitor firewall rules.
        /// Only enumerates when invalidated by Add/Remove (avoids expensive COM enumeration every 2s).
        /// </summary>
        public int GetRuleCount()
        {
            lock (_fwLock)
            {
                if (_cachedRuleCount >= 0) return _cachedRuleCount;

                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return 0;
                    int count = 0;
                    foreach (INetFwRule r in policy.Rules)
                    {
                        try
                        {
                            if (r.Name.StartsWith(FirewallRulePrefix)) count++;
                        }
                        catch { }
                    }
                    _cachedRuleCount = count;
                    return count;
                }
                catch (Exception ex)
                {
                    _logError($"FirewallService.GetRuleCount: {ex.Message}");
                    return 0;
                }
            }
        }

        public bool ApplyWebView2NetworkBlock(string path)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;

                    try { ((dynamic)policy).Rules.Remove("MyFirewall-Block-WebView2"); } catch { }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;

                    // Use dynamic (IDispatch) to avoid .NET 8/10 vtable marshalling failures.
                    dynamic rule = Activator.CreateInstance(ruleType)!;
                    rule.Name            = "MyFirewall-Block-WebView2";
                    rule.Description     = "Proactively blocks msedgewebview2.exe outbound network connections.";
                    rule.Protocol        = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY; // OK: no RemoteAddresses set
                    rule.ApplicationName = path;
                    rule.Direction       = (int)NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                    rule.Action          = (int)NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    rule.Enabled         = true;
                    rule.Profiles        = 7;

                    ((dynamic)policy).Rules.Add(rule);
                    _cachedRuleCount = -1;
                    return true;
                }
                catch (Exception ex)
                {
                    _logError($"ApplyWebView2NetworkBlock failed: {ex.Message}");
                    return false;
                }
            }
        }

        /// <summary>
        /// Short stable suffix identifying a specific executable path in a rule name,
        /// so one process name blocked at several locations (System32 + SysWOW64 + a
        /// copy elsewhere) gets one rule pair per location instead of colliding.
        /// </summary>
        private static string PathHash(string executablePath)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            byte[] hash = sha.ComputeHash(System.Text.Encoding.Unicode.GetBytes(executablePath.ToLowerInvariant()));
            return Convert.ToHexString(hash, 0, 4);
        }

        public bool AddBlockProcessRule(string appName, string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath) || executablePath == "N/A") return false;

            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;

                    string tag = $"{appName}-{PathHash(executablePath)}";
                    string outName = $"{FirewallRulePrefix}-APP-{tag}-OUT";
                    string inName  = $"{FirewallRulePrefix}-APP-{tag}-IN";

                    try { if (policy.Rules.Item(outName) != null) {} } catch {
                        dynamic ruleOut = Activator.CreateInstance(ruleType)!;
                        ruleOut.Name = outName;
                        ruleOut.Description = $"Auto-blocked process {appName} ({executablePath}) by TCP Monitor";
                        ruleOut.Protocol = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;

                        string? pfn = GetPackageFamilyName(executablePath);
                        if (pfn != null)
                        {
                            try { ruleOut.LocalAppPackageId = pfn; } catch { }
                        }
                        else
                        {
                            ruleOut.ApplicationName = executablePath;
                        }

                        ruleOut.Direction = (int)NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                        ruleOut.Action = (int)NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                        ruleOut.Enabled = true;
                        ruleOut.Profiles = 7;
                        ((dynamic)policy).Rules.Add(ruleOut);
                    }

                    try { if (policy.Rules.Item(inName) != null) {} } catch {
                        dynamic ruleIn = Activator.CreateInstance(ruleType)!;
                        ruleIn.Name = inName;
                        ruleIn.Description = $"Auto-blocked process {appName} ({executablePath}) by TCP Monitor";
                        ruleIn.Protocol = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;

                        string? pfn = GetPackageFamilyName(executablePath);
                        if (pfn != null)
                        {
                            try { ruleIn.LocalAppPackageId = pfn; } catch { }
                        }
                        else
                        {
                            ruleIn.ApplicationName = executablePath;
                        }

                        ruleIn.Direction = (int)NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                        ruleIn.Action = (int)NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                        ruleIn.Enabled = true;
                        ruleIn.Profiles = 7;
                        ((dynamic)policy).Rules.Add(ruleIn);
                    }

                    _cachedRuleCount = -1;
                    return true;
                }
                catch (Exception ex)
                {
                    _logError($"FirewallService.AddBlockProcessRule({appName}): {ex.Message}");
                    return false;
                }
            }
        }

        private static string? GetPackageFamilyName(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath)) return null;
            string pathLower = executablePath.ToLowerInvariant();
            if (!pathLower.Contains("\\windowsapps\\") && !pathLower.Contains("\\systemapps\\"))
                return null;

            string? folderName = null;
            var directory = System.IO.Path.GetDirectoryName(executablePath);
            while (!string.IsNullOrEmpty(directory))
            {
                string dirName = System.IO.Path.GetFileName(directory);
                string parent = System.IO.Path.GetDirectoryName(directory) ?? "";
                if (parent.ToLowerInvariant().EndsWith("\\windowsapps") || parent.ToLowerInvariant().EndsWith("\\systemapps"))
                {
                    folderName = dirName;
                    break;
                }
                directory = parent;
            }

            if (string.IsNullOrEmpty(folderName)) return null;

            var parts = folderName.Split('_');
            if (parts.Length < 2) return folderName;

            return parts[0] + "_" + parts[parts.Length - 1];
        }

        public void RemoveBlockProcessRule(string appName)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;

                    // One process name may be blocked at several paths, each with its
                    // own hashed rule pair — enumerate by prefix and remove them all.
                    // The trailing dash keeps "foo" from matching "foo2" rules, and
                    // still matches the legacy un-hashed names ("...-APP-foo-OUT").
                    string prefix = $"{FirewallRulePrefix}-APP-{appName}-";
                    var toRemove = new List<string>();
                    foreach (INetFwRule r in policy.Rules)
                    {
                        try { if (r.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) toRemove.Add(r.Name); }
                        catch { }
                    }
                    foreach (var name in toRemove) policy.Rules.Remove(name);

                    // Legacy pre-hash names (exact, no trailing dash component).
                    try { policy.Rules.Remove($"{FirewallRulePrefix}-APP-{appName}-OUT"); } catch { }
                    try { policy.Rules.Remove($"{FirewallRulePrefix}-APP-{appName}-IN"); } catch { }

                    _cachedRuleCount = -1;
                }
                catch (Exception ex) { _logError($"FirewallService.RemoveBlockProcessRule({appName}): {ex.Message}"); }
            }
        }

        public void RemoveWebView2NetworkBlock()
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;
                    try { policy.Rules.Remove("MyFirewall-Block-WebView2"); } catch { }
                    _cachedRuleCount = -1;
                }
                catch (Exception ex) { _logError($"RemoveWebView2NetworkBlock failed: {ex.Message}"); }
            }
        }

        /// <summary>
        /// Returns all TCP-Monitor firewall rules as (RuleName, IP, Enabled) tuples.
        /// </summary>
        public List<(string Name, string IP, bool Enabled)> GetAllRules()
        {
            var rules = new List<(string, string, bool)>();
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return rules;
                    foreach (INetFwRule r in policy.Rules)
                    {
                        try
                        {
                            if (r.Name.StartsWith(FirewallRulePrefix))
                                rules.Add((r.Name, r.RemoteAddresses ?? "", r.Enabled));
                        }
                        catch { }
                    }
                }
                catch (Exception ex) { _logError($"FirewallService.GetAllRules: {ex.Message}"); }
            }
            return rules;
        }
    }
}
