using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Solution.Scanning;

namespace LuckyGuard.Tests;

public sealed class DeveloperProjectScannerTests
{
    [Fact]
    public async Task CleanProject_GetsDeveloperSurfaceCleanVerdict()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string project = Path.Combine(dir, "clean.csproj");
            File.WriteAllText(project, "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            var coordinator = new ScanCoordinator([new BaselineTargetScanner(), new DeveloperProjectScanner()]);
            var result = await coordinator.ScanAsync(new ScanTarget(ScanTargetKind.Project, project));
            Assert.Empty(result.Errors);
            Assert.Empty(result.Findings);
            Assert.Equal(Verdict.Clean, result.Verdict);
            Assert.Equal(1, result.Metrics["msbuildFilesAnalyzed"]);
        }
        finally { Directory.Delete(dir, true); }
    }
}
