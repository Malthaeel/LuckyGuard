using System.Text.RegularExpressions;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.MSBuild.Analysis;

public sealed partial class RspFileAnalyzer
{
    [GeneratedRegex(@"(?i)(/logger:|/l:|/distributedlogger:)")]
    private static partial Regex LoggerSwitchRegex();
    [GeneratedRegex(@"(?i)(CustomBeforeMicrosoftCommonTargets|CustomAfterMicrosoftCommonTargets)")]
    private static partial Regex CustomTargetsRegex();
    [GeneratedRegex(@"(?i)(%TEMP%|%APPDATA%|%LOCALAPPDATA%|\\AppData\\|\\Temp\\|https?://|^\\\\)")]
    private static partial Regex RiskyLocationRegex();

    public IReadOnlyList<DetectionFinding> Analyze(string path, long maxBytes)
    {
        var findings = new List<DetectionFinding>();
        var info = new FileInfo(path);
        if (!info.Exists || info.Length > Math.Min(maxBytes, 4L * 1024 * 1024)) return findings;
        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return findings; }

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            bool logger = LoggerSwitchRegex().IsMatch(line);
            bool customTargets = CustomTargetsRegex().IsMatch(line);
            bool risky = RiskyLocationRegex().IsMatch(line);
            if (!(risky && (logger || customTargets))) continue;

            findings.Add(new DetectionFinding(
                logger ? "LG.MSBUILD.RSP_RISKY_LOGGER" : "LG.MSBUILD.RSP_RISKY_TARGET_OVERRIDE",
                "Suspicious MSBuild response-file option",
                DetectionCategory.MSBuild,
                DetectionSeverity.High,
                DetectionConfidence.Heuristic,
                "Directory.Build.rsp can affect MSBuild before the project is evaluated; this option references a risky location.",
                path,
                [new Evidence("rsp-option", line, $"line {i + 1}")]));
        }
        return findings;
    }
}
