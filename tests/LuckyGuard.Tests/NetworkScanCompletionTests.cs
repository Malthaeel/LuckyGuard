using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Windows.Network;

namespace LuckyGuard.Tests;

public sealed class NetworkScanCompletionTests
{
    [Fact]
    public void SuccessfulNetworkPassWithoutFindings_IsClean()
    {
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.System, "network") };
        Assert.Equal(Verdict.NotAssessed, result.Verdict);

        NetworkScanCompletion.MarkAssessed(result);

        Assert.Equal(Verdict.Clean, result.Verdict);
    }

    [Fact]
    public void NetworkPassWithError_RemainsNotAssessedForResolverToMarkIncomplete()
    {
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.System, "network") };
        result.Errors.Add(new ScanError("NetworkScanner", "test error"));

        NetworkScanCompletion.MarkAssessed(result);

        Assert.Equal(Verdict.NotAssessed, result.Verdict);
    }
}
