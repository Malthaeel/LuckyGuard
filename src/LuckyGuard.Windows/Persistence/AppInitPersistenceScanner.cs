using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Windows.Analysis;
using Microsoft.Win32;

namespace LuckyGuard.Windows.Persistence;

internal static class AppInitPersistenceScanner
{
    private const string WindowsPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(WindowsPath, false);
                if (key is null) continue;
                int enabled = Convert.ToInt32(key.GetValue("LoadAppInit_DLLs", 0));
                string dlls = key.GetValue("AppInit_DLLs")?.ToString() ?? string.Empty;
                if (enabled == 0 || string.IsNullOrWhiteSpace(dlls)) continue;
                var evidence = new List<Evidence> { new("dlls", PersistenceFindingFactory.Truncate(dlls)), new("registryView", view.ToString()) };
                bool writable = dlls.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries).Any(CommandRiskAnalyzer.IsUserWritablePath);
                result.Findings.Add(new DetectionFinding("LG.PERSISTENCE.APPINIT_DLLS", "AppInit_DLLs loading is enabled", DetectionCategory.Persistence,
                    writable ? DetectionSeverity.High : DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                    writable ? "AppInit_DLLs is enabled and references a user-writable location." : "AppInit_DLLs is enabled with configured DLLs. This legacy injection mechanism should be reviewed.",
                    $"HKLM\\{WindowsPath}", evidence));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                if (!ignoreInaccessible) result.Errors.Add(new ScanError("AppInitPersistenceScanner", ex.Message, WindowsPath));
            }
        }
    }
}
