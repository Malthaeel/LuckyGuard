using System.Text.RegularExpressions;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.Source;

public sealed partial class SourceFileAnalyzer
{
    private static readonly string[] LuckyWareMarkers =
    [
        "VccLibaries", "SDKInfector", "VCCHelp", "NtExploreProcess", "Bombakla", "Rundollay", "InfectSDK", "InfectINIT"
    ];

    [GeneratedRegex(@"(?:\\x[0-9A-Fa-f]{2}){32,}", RegexOptions.Compiled)]
    private static partial Regex LongHexBlobRegex();

    public IReadOnlyList<DetectionFinding> Analyze(string path, long maxBytes)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length > Math.Min(maxBytes, 16L * 1024 * 1024)) return Array.Empty<DetectionFinding>();

        string text;
        try { text = File.ReadAllText(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return Array.Empty<DetectionFinding>(); }
        return AnalyzeText(text, path);
    }

    public IReadOnlyList<DetectionFinding> AnalyzeText(string text, string displayPath)
    {
        var findings = new List<DetectionFinding>();
        var foundMarkers = LuckyWareMarkers.Where(m => text.Contains(m, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (foundMarkers.Length > 0)
        {
            findings.Add(new DetectionFinding(
                "LW.SOURCE.KNOWN_MARKER",
                "LuckyWare-associated source marker",
                DetectionCategory.Source,
                foundMarkers.Length >= 2 ? DetectionSeverity.High : DetectionSeverity.Suspicious,
                DetectionConfidence.Community,
                $"Source contains LuckyWare-associated reverse-engineering marker(s): {string.Join(", ", foundMarkers)}.",
                displayPath,
                foundMarkers.Select(m => new Evidence("marker", m)).ToArray()));
        }

        if (Path.GetFileName(displayPath).Equals("imgui_impl_win32.cpp", StringComparison.OrdinalIgnoreCase))
        {
            var blob = LongHexBlobRegex().Match(text);
            if (blob.Success)
            {
                findings.Add(new DetectionFinding("LW.SOURCE.IMGUI_OBFUSCATED_BLOB", "Suspicious ImGui source modification", DetectionCategory.Source, DetectionSeverity.Suspicious, DetectionConfidence.Community, "imgui_impl_win32.cpp contains an unusually long escaped hexadecimal blob associated with reported source-poisoning patterns.", displayPath, [new Evidence("escaped-hex-bytes", $"{blob.Length} characters")]));
            }
        }

        return findings;
    }
}
