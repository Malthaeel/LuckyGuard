using LuckyGuard.Core.Detection;

namespace LuckyGuard.SDK.Analysis;

public sealed class SdkSourceAnalyzer
{
    private static readonly string[] Markers = ["namespace VccLibaries", "namespace SDKInfector", "VCCHelp", "NtExploreProcess", "InfectSDK", "InfectINIT"];
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".h", ".hpp", ".hh", ".inl", ".cpp", ".c" };

    public IReadOnlyList<DetectionFinding> Analyze(string path, long maxFileBytes)
    {
        var findings = new List<DetectionFinding>();
        if (!Extensions.Contains(Path.GetExtension(path))) return findings;
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0 || info.Length > Math.Min(maxFileBytes, 16L * 1024 * 1024)) return findings;
        string text = File.ReadAllText(path);
        string[] matched = Markers.Where(m => text.Contains(m, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (matched.Length == 0) return findings;
        findings.Add(new DetectionFinding(
            "LW.SDK.KNOWN_MARKER",
            "LuckyWare-related marker in SDK/toolchain source",
            DetectionCategory.SDK,
            matched.Length >= 2 ? DetectionSeverity.Critical : DetectionSeverity.High,
            DetectionConfidence.Community,
            "A Windows SDK/MSVC source file contains community-reported LuckyWare poisoning markers. LuckyGuard will not modify SDK files; repair/reinstall should be used after confirmation.",
            path,
            matched.Select(x => new Evidence("marker", x)).ToArray()));
        return findings;
    }
}
