using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Persistence;

namespace LuckyGuard.Tests;

public sealed class ServiceImageAnalyzerTests
{
    [Fact]
    public void MissingDemandStartCpuzDriver_IsInformational()
    {
        var finding = ServiceImageAnalyzer.Analyze(
            "cpuz154", @"\??\C:\WINDOWS\temp\cpuz154\cpuz154_x64.sys", 3, false,
            @"HKLM\SYSTEM\CurrentControlSet\Services\cpuz154");
        Assert.NotNull(finding);
        Assert.Equal("LG.PERSISTENCE.ORPHANED_CPUID_SERVICE", finding!.Id);
        Assert.Equal(DetectionSeverity.Informational, finding.Severity);
    }

    [Fact]
    public void ExistingTemporaryDriverService_RemainsHigh()
    {
        var finding = ServiceImageAnalyzer.Analyze(
            "driverx", @"C:\Windows\Temp\driverx\driverx.sys", 2, true,
            @"HKLM\SYSTEM\CurrentControlSet\Services\driverx");
        Assert.NotNull(finding);
        Assert.Equal(DetectionSeverity.High, finding!.Severity);
    }
}
