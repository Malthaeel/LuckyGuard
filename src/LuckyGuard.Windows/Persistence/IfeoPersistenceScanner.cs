using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Windows.Analysis;
using Microsoft.Win32;

namespace LuckyGuard.Windows.Persistence;

internal static class IfeoPersistenceScanner
{
    private const string IfeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private static readonly string[] KnownDebuggers = ["vsjitdebugger.exe", "windbg.exe", "ntsd.exe", "cdb.exe", "devenv.exe"];

    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        int debuggerEntries = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var root = baseKey.OpenSubKey(IfeoPath, false);
                if (root is null) continue;
                foreach (string image in root.GetSubKeyNames())
                {
                    using var key = root.OpenSubKey(image, false);
                    string? debugger = key?.GetValue("Debugger")?.ToString();
                    if (string.IsNullOrWhiteSpace(debugger) || !seen.Add(image + "=" + debugger)) continue;
                    debuggerEntries++;
                    string location = $"HKLM\\{IfeoPath}\\{image}::Debugger";
                    var commandFinding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.IFEO_COMMAND", "Suspicious IFEO debugger command", location, debugger, extraEvidence: [new Evidence("registryView", view.ToString())]);
                    if (commandFinding is not null) { result.Findings.Add(commandFinding); continue; }
                    string firstToken = debugger.Trim().Trim('"').Split(' ', 2)[0];
                    string file = Path.GetFileName(firstToken);
                    if (!KnownDebuggers.Contains(file, StringComparer.OrdinalIgnoreCase) || CommandRiskAnalyzer.IsUserWritablePath(debugger))
                    {
                        result.Findings.Add(new DetectionFinding("LG.PERSISTENCE.IFEO_DEBUGGER", "Unexpected Image File Execution Options debugger", DetectionCategory.Persistence,
                            DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                            "IFEO can intentionally launch a debugger whenever the target image starts. The configured debugger is not one of LuckyGuard's small known-debugger allowlist and should be reviewed.",
                            location, [new Evidence("targetImage", image), new Evidence("debugger", PersistenceFindingFactory.Truncate(debugger)), new Evidence("registryView", view.ToString())]));
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                if (!ignoreInaccessible) result.Errors.Add(new ScanError("IfeoPersistenceScanner", ex.Message, IfeoPath));
            }
        }
        result.Metrics["ifeoDebuggerEntriesInspected"] = debuggerEntries;
    }
}
