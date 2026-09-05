using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Detection.Scoring;

namespace LuckyGuard.Tests;

public sealed class VerdictResolverTests
{
    [Fact]
    public void Phase0Result_RemainsNotAssessed()
    {
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.Path, "."), Verdict = Verdict.NotAssessed };
        Assert.Equal(Verdict.NotAssessed, VerdictResolver.Resolve(result));
        Assert.Equal(10, VerdictResolver.ToExitCode(Verdict.NotAssessed));
    }

    [Fact]
    public void CriticalFinding_Wins()
    {
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.File, "sample.bin") };
        result.Findings.Add(new DetectionFinding("TEST.CRITICAL", "test", DetectionCategory.Generic, DetectionSeverity.Critical, DetectionConfidence.Confirmed, "fixture"));
        Assert.Equal(Verdict.Critical, VerdictResolver.Resolve(result));
        Assert.Equal(4, VerdictResolver.ToExitCode(Verdict.Critical));
    }

    [Fact]
    public void ErrorsWithoutFindings_AreIncomplete()
    {
        var result = new ScanResult { Target = new ScanTarget(ScanTargetKind.File, "missing.bin") };
        result.Errors.Add(new ScanError("test", "missing"));
        Assert.Equal(Verdict.Incomplete, VerdictResolver.Resolve(result));
    }
}
