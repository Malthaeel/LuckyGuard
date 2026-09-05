using System.Text;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.Suo;

public sealed class SuoFileAnalyzer
{
    private static readonly byte[] CompoundMagic = [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1];
    private static readonly string[] Markers = ["NtExploreProcess", "VccLibaries", "SDKInfector", "VCCHelp"];

    public IReadOnlyList<DetectionFinding> Analyze(string path, long maxFileBytes)
    {
        var findings = new List<DetectionFinding>();
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0 || info.Length > maxFileBytes) return findings;
        byte[] data = File.ReadAllBytes(path);
        bool compound = data.Length >= CompoundMagic.Length && data.AsSpan(0, CompoundMagic.Length).SequenceEqual(CompoundMagic);
        if (!compound) return findings;

        string ascii = Encoding.ASCII.GetString(data);
        string unicode = Encoding.Unicode.GetString(data);
        var matched = Markers.Where(m => ascii.Contains(m, StringComparison.OrdinalIgnoreCase) || unicode.Contains(m, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (matched.Length > 0)
        {
            findings.Add(new DetectionFinding(
                "LW.SUO.KNOWN_MARKER",
                "LuckyWare-related marker in .suo",
                DetectionCategory.SUO,
                matched.Length >= 2 ? DetectionSeverity.High : DetectionSeverity.Suspicious,
                DetectionConfidence.Community,
                "The .suo compound file contains community-reported LuckyWare developer-infection markers. LuckyGuard does not execute or deserialize the embedded Visual Studio state.",
                path,
                matched.Select(x => new Evidence("marker", x)).ToArray()));
        }
        return findings;
    }
}
