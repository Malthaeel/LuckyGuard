using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Analysis;

namespace LuckyGuard.Windows.Processes;

public static class ProcessAnalyzer
{
    private static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
        "dwm.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "dllhost.exe",
        "sndvol.exe", "dispdiag.exe", "isoburn.exe"
    };

    public static IReadOnlyList<DetectionFinding> Analyze(ProcessSnapshot process)
    {
        var findings = new List<DetectionFinding>();
        string name = process.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? process.Name : process.Name + ".exe";
        string? path = process.ImagePath;

        if (path is not null && SystemNames.Contains(name) && !IsUnderWindowsDirectory(path))
        {
            findings.Add(new DetectionFinding(
                "LW.PROCESS.SYSTEM_NAME_OUTSIDE_WINDOWS",
                "Windows system process name outside Windows directory",
                DetectionCategory.Process,
                DetectionSeverity.High,
                DetectionConfidence.Heuristic,
                "A process uses a Windows system executable name but its image is outside the Windows directory. This can indicate masquerading; the process name alone is not treated as malicious.",
                path,
                [new Evidence("processId", process.ProcessId.ToString()), new Evidence("processName", name), new Evidence("parentPid", process.ParentProcessId.ToString())]));
        }

        if (path is not null && CommandRiskAnalyzer.IsTempPath(path) && IsTimestampStyleExecutable(Path.GetFileName(path)))
        {
            findings.Add(new DetectionFinding(
                "LW.PROCESS.TIMESTAMP_TEMP_EXECUTABLE",
                "Timestamp-style executable running from temporary directory",
                DetectionCategory.Process,
                DetectionSeverity.Suspicious,
                DetectionConfidence.Heuristic,
                "The running executable matches a reported LuckyWare-style short-prefix timestamp filename and is executing from a temporary directory.",
                path,
                [new Evidence("processId", process.ProcessId.ToString()), new Evidence("processName", name)]));
        }

        var commandAssessment = CommandRiskAnalyzer.Analyze(process.CommandLine);
        if (commandAssessment is not null)
        {
            findings.Add(new DetectionFinding(
                commandAssessment.Severity == DetectionSeverity.Critical ? "LW.PROCESS.CONFIRMED_C2_COMMAND" : "LG.PROCESS.SUSPICIOUS_COMMAND",
                "Suspicious running process command line",
                DetectionCategory.Process,
                commandAssessment.Severity,
                commandAssessment.Confidence,
                commandAssessment.Reason,
                path,
                commandAssessment.Evidence.Concat([new Evidence("processId", process.ProcessId.ToString()), new Evidence("processName", name)]).ToArray()));
        }

        return findings;
    }

    private static bool IsUnderWindowsDirectory(string path)
    {
        string windows = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return false; }
        return full.StartsWith(windows, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTimestampStyleExecutable(string name)
    {
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
        string stem = Path.GetFileNameWithoutExtension(name);
        int letters = 0;
        while (letters < stem.Length && char.IsLetter(stem[letters]) && letters < 3) letters++;
        if (letters is < 2 or > 3) return false;
        string digits = stem[letters..];
        return digits.Length is >= 10 and <= 13 && digits.All(char.IsDigit);
    }
}
