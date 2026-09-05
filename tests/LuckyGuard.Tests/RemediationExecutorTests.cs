using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Quarantine;
using LuckyGuard.Remediation.Execution;
using LuckyGuard.Remediation.Models;

namespace LuckyGuard.Tests;

public sealed class RemediationExecutorTests
{
    [Fact]
    public void QuarantineAction_CanBeRolledBack()
    {
        using var temp = new TestTempDirectory();
        string file = Path.Combine(temp.Path, "bad.exe");
        File.WriteAllText(file, "payload");
        var plan = new RemediationPlan
        {
            PlanId = "plan",
            CreatedAtUtc = DateTimeOffset.UtcNow,
            SourceTarget = new ScanTarget(ScanTargetKind.File, file),
            SourceVerdict = Verdict.Critical,
            SourceFindings = 1,
            Actions = [new RemediationAction
            {
                Id="a", Kind=RemediationActionKind.QuarantineFile, FindingId="LW.IOC.SHA256_MATCH",
                Title="quarantine", Severity=DetectionSeverity.Critical, Confidence=DetectionConfidence.Confirmed,
                Target=file, AutoEligible=true, RequiresElevation=false, Reason="test"
            }]
        };
        var quarantine = new QuarantineManager(Path.Combine(temp.Path, "q"));
        var executor = new RemediationExecutor(quarantine, Path.Combine(temp.Path, "journals"));
        var result = executor.Apply(plan);
        Assert.True(result.Success);
        Assert.False(File.Exists(file));
        Assert.Single(result.Applied);

        var restored = executor.Rollback(result.ExecutionId);
        Assert.True(File.Exists(file));
        Assert.Equal("payload", File.ReadAllText(file));
        Assert.Single(restored);
    }

    [Fact]
    public void Executor_RefusesIncompleteSourceVerdict()
    {
        using var temp = new TestTempDirectory();
        var plan = new RemediationPlan
        {
            PlanId="p", CreatedAtUtc=DateTimeOffset.UtcNow,
            SourceTarget=new ScanTarget(ScanTargetKind.System,"system"), SourceVerdict=Verdict.Incomplete
        };
        var executor = new RemediationExecutor(new QuarantineManager(Path.Combine(temp.Path,"q")), Path.Combine(temp.Path,"j"));
        Assert.Throws<InvalidOperationException>(() => executor.Apply(plan));
    }
}
