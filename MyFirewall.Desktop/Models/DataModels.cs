using System;
using System.Windows.Media;

namespace MyFirewall.Desktop.Models
{
    public enum AlertSeverity
    {
        Info,
        Warning,
        Critical
    }

    public class AlertEntry
    {
        // Fix #E: Static frozen brushes — avoid per-access allocation on every UI refresh.
        private static readonly SolidColorBrush _infoColor;
        private static readonly SolidColorBrush _warningColor;
        private static readonly SolidColorBrush _criticalColor;
        private static readonly SolidColorBrush _defaultColor;
        private static readonly SolidColorBrush _infoBg;
        private static readonly SolidColorBrush _warningBg;
        private static readonly SolidColorBrush _criticalBg;
        private static readonly SolidColorBrush _defaultBg;
        private static readonly SolidColorBrush _infoBorder;
        private static readonly SolidColorBrush _warningBorder;
        private static readonly SolidColorBrush _criticalBorder;
        private static readonly SolidColorBrush _defaultBorder;

        static AlertEntry()
        {
            static SolidColorBrush Make(string hex) {
                var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
                b.Freeze();
                return b;
            }
            _infoColor     = Make("#58A6FF");
            _warningColor  = Make("#D29922");
            _criticalColor = Make("#F85149");
            _defaultColor  = Make("#8B949E");
            _infoBg        = Make("#0D2137");
            _warningBg     = Make("#2A2316");
            _criticalBg    = Make("#2A1616");
            _defaultBg     = Make("#161B22");
            _infoBorder    = Make("#1F4068");
            _warningBorder = Make("#5C4B1F");
            _criticalBorder= Make("#5C1F1F");
            _defaultBorder = Make("#30363D");
        }

        public string Message { get; set; } = "";
        public string Timestamp { get; set; } = DateTime.Now.ToString("HH:mm:ss");
        public AlertSeverity Severity { get; set; } = AlertSeverity.Warning;

        public SolidColorBrush AlertColor => Severity switch
        {
            AlertSeverity.Info     => _infoColor,
            AlertSeverity.Warning  => _warningColor,
            AlertSeverity.Critical => _criticalColor,
            _                      => _defaultColor
        };

        public string AlertIcon => Severity switch
        {
            AlertSeverity.Info     => "ℹ",
            AlertSeverity.Warning  => "⚠",
            AlertSeverity.Critical => "🛑",
            _                      => "•"
        };

        public SolidColorBrush AlertBgColor => Severity switch
        {
            AlertSeverity.Info     => _infoBg,
            AlertSeverity.Warning  => _warningBg,
            AlertSeverity.Critical => _criticalBg,
            _                      => _defaultBg
        };

        public SolidColorBrush AlertBorderColor => Severity switch
        {
            AlertSeverity.Info     => _infoBorder,
            AlertSeverity.Warning  => _warningBorder,
            AlertSeverity.Critical => _criticalBorder,
            _                      => _defaultBorder
        };
    }

    public class BlockedIPMetadata
    {
        public string Application { get; set; } = "Unknown";
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }

    public class BlockedIPEntry
    {
        public string IP { get; set; } = "";
        public string Application { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string DisplayTimestamp => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    }

    public class IgnoredAppEntry
    {
        public string Application { get; set; } = "";
    }

    /// <summary>
    /// One live taskhostw.exe instance with its hosted COM handler resolved to the
    /// DLL that actually runs inside it — the taskhostw analog of the svchost
    /// PID→service mapping used in triage.
    /// </summary>
    public class TaskHostDllEntry
    {
        public int PID { get; set; }
        /// <summary>Handler argument from the command line: a COM CLSID ({...}) or a -dllname value.</summary>
        public string Handler { get; set; } = "";
        /// <summary>DLL resolved from the CLSID via InprocServer32, when found.</summary>
        public string DllPath { get; set; } = "";
        /// <summary>Scheduled tasks whose ComHandler ClassId matches this instance's CLSID.</summary>
        public string TaskNames { get; set; } = "";
        /// <summary>Live remote connections currently owned by this PID.</summary>
        public int ConnectionCount { get; set; }
        public string CommandLine { get; set; } = "";
        public int ModuleCount { get; set; }
        public string Display => $"PID {PID} · {Handler}";
        public string TrafficFlag => ConnectionCount > 0 ? $"🔌 {ConnectionCount} conn" : "no traffic";
    }
}

