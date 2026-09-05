using System.Text.RegularExpressions;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.Windows.Analysis;

public static partial class CommandRiskAnalyzer
{
    private static readonly string[] ShellTokens =
    [
        "powershell", "pwsh", "cmd.exe", "cmd /", "mshta", "wscript", "cscript",
        "rundll32", "regsvr32", "certutil", "bitsadmin"
    ];

    private static readonly string[] DownloadTokens =
    [
        "invoke-webrequest", "iwr ", "downloadstring", "downloadfile", "webclient",
        "curl ", "curl.exe", "wget ", "http://", "https://"
    ];

    private static readonly string[] ObfuscationTokens =
    [
        "encodedcommand", "-enc ", "frombase64string", "invoke-expression", "iex ",
        "windowstyle hidden", "-w hidden", "executionpolicy bypass", "-ep bypass"
    ];

    private static readonly string[] CommunityMarkers =
    [
        "berok.exe", "retev.exe", "retev.php", "vcchelp", "ntexploreprocess",
        "vcclibaries", "sdkinfector"
    ];

    public static CommandAssessment? Analyze(string? command, bool persistenceContext = false)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        string normalized = command.Trim().ToLowerInvariant();
        var evidence = new List<Evidence>();

        if (normalized.Contains("luckyware.cy", StringComparison.Ordinal))
        {
            evidence.Add(new Evidence("confirmedC2", "luckyware.cy", "runtime-verified LuckyWare infrastructure"));
            return new CommandAssessment(DetectionSeverity.Critical, DetectionConfidence.Confirmed,
                "Command references confirmed LuckyWare command-and-control infrastructure.", evidence);
        }

        string? marker = CommunityMarkers.FirstOrDefault(token => normalized.Contains(token, StringComparison.Ordinal));
        if (marker is not null)
        {
            evidence.Add(new Evidence("luckywareMarker", marker, "community/reverse-engineering indicator"));
            return new CommandAssessment(DetectionSeverity.High, DetectionConfidence.Community,
                "Command contains a LuckyWare-associated community/reverse-engineering marker.", evidence);
        }

        bool shell = TryAddTokenEvidence(normalized, ShellTokens, "shell", evidence);
        bool download = TryAddTokenEvidence(normalized, DownloadTokens, "download", evidence);
        bool obfuscation = TryAddTokenEvidence(normalized, ObfuscationTokens, "evasion", evidence);
        bool temp = ContainsAny(normalized, ["\\temp\\", "%temp%", "$env:temp", "\\appdata\\local\\temp\\"]);
        bool userWritable = ContainsAny(normalized, ["\\appdata\\", "%appdata%", "%localappdata%", "\\downloads\\", "\\desktop\\"]);
        bool timestampName = TimestampExecutableRegex().IsMatch(normalized);

        if (temp) evidence.Add(new Evidence("location", "temporary directory"));
        if (timestampName) evidence.Add(new Evidence("filenamePattern", "2-3 letters + 10-13 digits executable"));

        if (shell && (download || obfuscation) && (temp || userWritable || download && obfuscation))
            return new CommandAssessment(DetectionSeverity.High, DetectionConfidence.Heuristic,
                "Shell execution combines download/obfuscation behavior with a risky execution context.", evidence);

        if (shell && download && persistenceContext)
            return new CommandAssessment(DetectionSeverity.High, DetectionConfidence.Heuristic,
                "Persistence entry launches a shell-based downloader.", evidence);

        if (shell && obfuscation)
            return new CommandAssessment(DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                "Command uses shell execution with obfuscation or execution-policy evasion.", evidence);

        if (timestampName && temp)
            return new CommandAssessment(DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                "Executable name matches a reported LuckyWare-style timestamp pattern inside a temporary directory.", evidence);

        return null;
    }

    public static bool IsUserWritablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string p = Environment.ExpandEnvironmentVariables(path).Replace('/', '\\').ToLowerInvariant();
        return p.Contains("\\users\\", StringComparison.Ordinal) &&
               (p.Contains("\\appdata\\", StringComparison.Ordinal) || p.Contains("\\downloads\\", StringComparison.Ordinal) || p.Contains("\\desktop\\", StringComparison.Ordinal) || p.Contains("\\temp\\", StringComparison.Ordinal));
    }

    public static bool IsTempPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string p = Environment.ExpandEnvironmentVariables(path).Replace('/', '\\').ToLowerInvariant();
        return p.Contains("\\temp\\", StringComparison.Ordinal) || p.Contains("\\appdata\\local\\temp\\", StringComparison.Ordinal);
    }

    private static bool TryAddTokenEvidence(string text, IEnumerable<string> tokens, string kind, List<Evidence> evidence)
    {
        string? match = tokens.FirstOrDefault(token => text.Contains(token, StringComparison.Ordinal));
        if (match is null) return false;
        evidence.Add(new Evidence(kind, match));
        return true;
    }

    private static bool ContainsAny(string text, IEnumerable<string> tokens) => tokens.Any(token => text.Contains(token, StringComparison.Ordinal));

    [GeneratedRegex("(?i)(?:^|[\\\\/\\s\"'])\\p{L}{2,3}\\d{10,13}\\.exe(?:$|[\\s\"'])", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampExecutableRegex();
}
