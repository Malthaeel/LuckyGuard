using LuckyGuard.Core.Detection;
using LuckyGuard.SDK.Analysis;

namespace LuckyGuard.Tests;

public sealed class SdkSourceAnalyzerTests
{
    [Fact]
    public void MultipleToolchainMarkers_AreCritical()
    {
        string file = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N") + ".h");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "namespace VccLibaries {} namespace SDKInfector {} NtExploreProcess");
        try
        {
            var finding = Assert.Single(new SdkSourceAnalyzer().Analyze(file, 1024 * 1024), x => x.Id == "LW.SDK.KNOWN_MARKER");
            Assert.Equal(DetectionSeverity.Critical, finding.Severity);
        }
        finally { File.Delete(file); }
    }
}
