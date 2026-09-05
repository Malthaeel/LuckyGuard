using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using Microsoft.Win32;

namespace LuckyGuard.Windows.Persistence;

internal static class RegistryPersistenceScanner
{
    private static readonly string[] RunPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ];

    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int entries = 0;
        foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        foreach (RegistryHive hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        foreach (string path in RunPaths)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(path, false);
                if (key is null) continue;
                foreach (string valueName in key.GetValueNames())
                {
                    string? command = key.GetValue(valueName)?.ToString();
                    string location = $"{hive}\\{path}::{valueName}";
                    if (!seen.Add(location + "=" + command)) continue;
                    entries++;
                    var finding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.RUN_COMMAND", "Suspicious Run/RunOnce command", location, command, extraEvidence: [new Evidence("registryView", view.ToString())]);
                    if (finding is not null) result.Findings.Add(finding);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                if (!ignoreInaccessible) result.Errors.Add(new ScanError("RegistryPersistenceScanner", ex.Message, $"{hive}\\{path}"));
            }
        }
        result.Metrics["runEntriesInspected"] = entries;
    }
}
