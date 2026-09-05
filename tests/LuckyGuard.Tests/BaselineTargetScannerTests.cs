using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Tests;

public sealed class BaselineTargetScannerTests
{
    [Fact]
    public async Task ExistingDirectory_IsValidatedButNotAssessed()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var coordinator = new ScanCoordinator([new BaselineTargetScanner()]);
            var result = await coordinator.ScanAsync(new ScanTarget(ScanTargetKind.Path, dir));
            Assert.Empty(result.Errors);
            Assert.Equal(Verdict.NotAssessed, result.Verdict);
            Assert.Equal(1, result.Metrics["targetExists"]);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task MissingTarget_IsIncomplete()
    {
        var coordinator = new ScanCoordinator([new BaselineTargetScanner()]);
        var result = await coordinator.ScanAsync(new ScanTarget(ScanTargetKind.Path, Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))));
        Assert.NotEmpty(result.Errors);
        Assert.Equal(Verdict.Incomplete, result.Verdict);
    }
}
