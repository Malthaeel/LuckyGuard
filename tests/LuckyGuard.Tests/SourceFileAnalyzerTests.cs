using LuckyGuard.Core.Detection;
using LuckyGuard.Source;

namespace LuckyGuard.Tests;

public sealed class SourceFileAnalyzerTests
{
    [Fact]
    public void KnownCommunityMarker_IsDetected()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string file = Path.Combine(dir, "sample.cpp");
            File.WriteAllText(file, "namespace VccLibaries { void NtExploreProcess(); }");
            var findings = new SourceFileAnalyzer().Analyze(file, 1024 * 1024);
            var finding = Assert.Single(findings, x => x.Id == "LW.SOURCE.KNOWN_MARKER");
            Assert.Equal(DetectionSeverity.High, finding.Severity);
            Assert.Equal(DetectionConfidence.Community, finding.Confidence);
        }
        finally { Directory.Delete(dir, true); }
    }
}
