using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardAlertSuppressorTests
{
    [Fact]
    public void DuplicateAlert_IsSuppressedWithinWindow()
    {
        var suppressor = new GuardAlertSuppressor(TimeSpan.FromMinutes(5));
        var finding = new DetectionFinding("LW.TEST", "test", DetectionCategory.IOC, DetectionSeverity.High, DetectionConfidence.Confirmed, "test", "C:\\x.exe");
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.File, "C:\\x.exe") };
        result.Findings.Add(finding);
        var alert = new GuardAlert(GuardAlertSource.FileSystem, DateTimeOffset.UtcNow, "C:\\x.exe", result);
        var now = DateTimeOffset.UtcNow;
        Assert.True(suppressor.ShouldEmit(alert, now));
        Assert.False(suppressor.ShouldEmit(alert, now.AddSeconds(30)));
        Assert.True(suppressor.ShouldEmit(alert, now.AddMinutes(6)));
    }

    [Fact]
    public void DifferentFinding_IsNotSuppressed()
    {
        var suppressor = new GuardAlertSuppressor(TimeSpan.FromMinutes(5));
        var a = Create("LW.A");
        var b = Create("LW.B");
        var now = DateTimeOffset.UtcNow;
        Assert.True(suppressor.ShouldEmit(a, now));
        Assert.True(suppressor.ShouldEmit(b, now.AddSeconds(1)));
    }

    private static GuardAlert Create(string id)
    {
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.File, "C:\\x.exe") };
        result.Findings.Add(new DetectionFinding(id, "test", DetectionCategory.IOC, DetectionSeverity.High, DetectionConfidence.Confirmed, "test", "C:\\x.exe"));
        return new GuardAlert(GuardAlertSource.FileSystem, DateTimeOffset.UtcNow, "C:\\x.exe", result);
    }
}
