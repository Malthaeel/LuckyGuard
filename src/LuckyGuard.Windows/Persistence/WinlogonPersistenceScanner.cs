using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using Microsoft.Win32;

namespace LuckyGuard.Windows.Persistence;

internal static class WinlogonPersistenceScanner
{
    private const string PathName = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PathName, false);
            if (key is null) return;
            string shell = key.GetValue("Shell")?.ToString() ?? "explorer.exe";
            string userinit = key.GetValue("Userinit")?.ToString() ?? string.Empty;
            result.Metrics["winlogonValuesInspected"] = 2;

            var shellCommand = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.WINLOGON_SHELL_COMMAND", "Suspicious Winlogon Shell command", $"HKLM\\{PathName}::Shell", shell);
            if (shellCommand is not null) result.Findings.Add(shellCommand);
            else if (!shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add(new DetectionFinding("LG.PERSISTENCE.WINLOGON_SHELL_CHANGED", "Non-default Winlogon Shell", DetectionCategory.Persistence,
                    DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                    "Winlogon Shell differs from the normal explorer.exe value. Kiosk/shell-replacement systems can do this legitimately, so review rather than auto-remove it.",
                    $"HKLM\\{PathName}::Shell", [new Evidence("value", PersistenceFindingFactory.Truncate(shell))]));

            var userCommand = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.WINLOGON_USERINIT_COMMAND", "Suspicious Winlogon Userinit command", $"HKLM\\{PathName}::Userinit", userinit);
            if (userCommand is not null) result.Findings.Add(userCommand);
            else if (!IsExpectedUserinit(userinit))
                result.Findings.Add(new DetectionFinding("LG.PERSISTENCE.WINLOGON_USERINIT_CHANGED", "Non-default Winlogon Userinit", DetectionCategory.Persistence,
                    DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                    "Winlogon Userinit contains a non-default command. This can be legitimate in managed environments but is a high-value persistence location.",
                    $"HKLM\\{PathName}::Userinit", [new Evidence("value", PersistenceFindingFactory.Truncate(userinit))]));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            if (!ignoreInaccessible) result.Errors.Add(new ScanError("WinlogonPersistenceScanner", ex.Message, PathName));
        }
    }

    private static bool IsExpectedUserinit(string value)
    {
        string normalized = Environment.ExpandEnvironmentVariables(value).Replace('/', '\\').Trim().TrimEnd(',').Trim();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        return normalized.Equals($"{windows}\\system32\\userinit.exe", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase);
    }
}
