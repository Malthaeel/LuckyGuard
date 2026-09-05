using LuckyGuard.Core.Detection;
using LuckyGuard.MSBuild.Analysis;

namespace LuckyGuard.Tests;

public sealed class RspFileAnalyzerTests
{
    [Fact]
    public void LoggerFromTemp_IsHigh()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string rsp = Path.Combine(dir, "Directory.Build.rsp");
            File.WriteAllText(rsp, "/logger:%TEMP%\\logger.dll");
            var findings = new RspFileAnalyzer().Analyze(rsp, 1024 * 1024);
            Assert.Contains(findings, x => x.Id == "LG.MSBUILD.RSP_RISKY_LOGGER" && x.Severity == DetectionSeverity.High);
        }
        finally { Directory.Delete(dir, true); }
    }
}
