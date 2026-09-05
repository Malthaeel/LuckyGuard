using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Processes;

namespace LuckyGuard.Tests;

public sealed class ProcessAnalyzerTests
{
    [Fact]
    public void SystemProcessNameOutsideWindows_IsHigh()
    {
        var snapshot = new ProcessSnapshot(100, 50, "svchost", @"C:\Users\Alice\AppData\Roaming\svchost.exe", null, false);
        var finding = Assert.Single(ProcessAnalyzer.Analyze(snapshot), x => x.Id == "LW.PROCESS.SYSTEM_NAME_OUTSIDE_WINDOWS");
        Assert.Equal(DetectionSeverity.High, finding.Severity);
    }

    [Fact]
    public void OrdinaryUserApplication_DoesNotTriggerMasqueradingRule()
    {
        var snapshot = new ProcessSnapshot(101, 50, "Discord", @"C:\Users\Alice\AppData\Local\Discord\Discord.exe", null, null);
        Assert.Empty(ProcessAnalyzer.Analyze(snapshot));
    }

    [Fact]
    public void ProcessCommandReferencingConfirmedC2_IsCritical()
    {
        var snapshot = new ProcessSnapshot(102, 50, "worker", @"C:\Temp\worker.exe", "worker.exe https://luckyware.cy/index.php", false);
        var finding = Assert.Single(ProcessAnalyzer.Analyze(snapshot), x => x.Id == "LW.PROCESS.CONFIRMED_C2_COMMAND");
        Assert.Equal(DetectionSeverity.Critical, finding.Severity);
        Assert.Equal(DetectionConfidence.Confirmed, finding.Confidence);
    }
}
