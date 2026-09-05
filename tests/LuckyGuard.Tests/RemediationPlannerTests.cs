using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Remediation.Models;
using LuckyGuard.Remediation.Planning;

namespace LuckyGuard.Tests;

public sealed class RemediationPlannerTests
{
    [Fact]
    public void ExactHashMatch_GeneratesEligibleQuarantine()
    {
        using var temp = new TestTempDirectory();
        string file = Path.Combine(temp.Path, "bad.exe"); File.WriteAllText(file, "x");
        var scan = Result(file, new DetectionFinding("LW.IOC.SHA256_MATCH", "hash", DetectionCategory.IOC, DetectionSeverity.Critical, DetectionConfidence.Confirmed, "x", file));
        var plan = new RemediationPlanner().Create(scan);
        var action = Assert.Single(plan.Actions);
        Assert.Equal(RemediationActionKind.QuarantineFile, action.Kind);
        Assert.True(action.AutoEligible);
    }

    [Fact]
    public void RcdEntrypoint_GeneratesEligibleQuarantine()
    {
        using var temp = new TestTempDirectory();
        string file = Path.Combine(temp.Path, "bad.exe"); File.WriteAllText(file, "x");
        var scan = Result(file, new DetectionFinding("LW.PE.ENTRYPOINT_RCD", "rcd", DetectionCategory.PE, DetectionSeverity.Critical, DetectionConfidence.Community, "x", file));
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.QuarantineFile, action.Kind);
        Assert.True(action.AutoEligible);
    }

    [Fact]
    public void HeuristicTempService_RemainsReviewOnly()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.SERVICE_TEMP_IMAGE", "service", DetectionCategory.Persistence, DetectionSeverity.High, DetectionConfidence.Heuristic, "x", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\x"), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.ReviewOnly, action.Kind);
        Assert.False(action.AutoEligible);
    }

    [Fact]
    public void ConfirmedRunValue_GeneratesRegistryRemoval()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.RUN_COMMAND", "run", DetectionCategory.Persistence, DetectionSeverity.Critical, DetectionConfidence.Confirmed, "x", "CurrentUser\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::Bad", [new Evidence("registryView", "Registry64")]), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.DeleteRegistryValue, action.Kind);
        Assert.Equal("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", action.Target);
        Assert.Equal("Bad", action.ValueName);
        Assert.Equal("Registry64", action.RegistryView);
        Assert.True(action.AutoEligible);
    }

    [Fact]
    public void CommunityRunValue_RemainsReviewOnly()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.RUN_COMMAND", "run", DetectionCategory.Persistence, DetectionSeverity.High, DetectionConfidence.Community, "x", "CurrentUser\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::Bad", [new Evidence("registryView", "Registry64")]), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.ReviewOnly, action.Kind);
    }

    [Fact]
    public void ConfirmedRunWithoutRegistryView_RemainsReviewOnly()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.RUN_COMMAND", "run", DetectionCategory.Persistence, DetectionSeverity.Critical, DetectionConfidence.Confirmed, "x", "CurrentUser\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::Bad"), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.ReviewOnly, action.Kind);
    }

    [Fact]
    public void DuplicateFileEvidence_ProducesOneQuarantineAction()
    {
        using var temp = new TestTempDirectory();
        string file = Path.Combine(temp.Path, "bad.exe"); File.WriteAllText(file, "x");
        var scan = new ScanResult { Target = new ScanTarget(ScanTargetKind.File, file), Verdict = Verdict.Critical };
        scan.Findings.Add(new DetectionFinding("LW.IOC.SHA256_MATCH", "hash", DetectionCategory.IOC, DetectionSeverity.Critical, DetectionConfidence.Confirmed, "x", file));
        scan.Findings.Add(new DetectionFinding("LW.PE.ENTRYPOINT_RCD", "rcd", DetectionCategory.PE, DetectionSeverity.Critical, DetectionConfidence.Community, "x", file));
        Assert.Single(new RemediationPlanner().Create(scan).Actions);
    }


    [Fact]
    public void ConfirmedScheduledTask_GeneratesRollbackBackedRemoval()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.TASK_COMMAND", "task", DetectionCategory.Persistence,
            DetectionSeverity.Critical, DetectionConfidence.Confirmed, "x", @"\LuckyGuardTest\BadTask"), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.DeleteScheduledTask, action.Kind);
        Assert.True(action.AutoEligible);
        Assert.True(action.RequiresElevation);
    }

    [Fact]
    public void CommunityScheduledTask_RemainsReviewOnly()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.TASK_COMMAND", "task", DetectionCategory.Persistence,
            DetectionSeverity.High, DetectionConfidence.Community, "x", @"\LuckyGuardTest\BadTask"), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.ReviewOnly, action.Kind);
    }

    [Fact]
    public void ConfirmedCriticalService_GeneratesStoppedServiceRemovalPlan()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.SERVICE_COMMAND", "service", DetectionCategory.Persistence,
            DetectionSeverity.Critical, DetectionConfidence.Confirmed, "x", @"HKLM\SYSTEM\CurrentControlSet\Services\BadSvc",
            [new Evidence("service", "BadSvc")]), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.DeleteService, action.Kind);
        Assert.Equal("BadSvc", action.Target);
        Assert.True(action.AutoEligible);
    }

    [Fact]
    public void ConfirmedHighService_RemainsReviewOnly()
    {
        var scan = Result("system", new DetectionFinding("LG.PERSISTENCE.SERVICE_COMMAND", "service", DetectionCategory.Persistence,
            DetectionSeverity.High, DetectionConfidence.Confirmed, "x", @"HKLM\SYSTEM\CurrentControlSet\Services\BadSvc",
            [new Evidence("service", "BadSvc")]), ScanTargetKind.System);
        var action = Assert.Single(new RemediationPlanner().Create(scan).Actions);
        Assert.Equal(RemediationActionKind.ReviewOnly, action.Kind);
    }

    private static ScanResult Result(string target, DetectionFinding finding, ScanTargetKind kind = ScanTargetKind.File)
    {
        var result = new ScanResult { Target = new ScanTarget(kind, target), Verdict = finding.Severity == DetectionSeverity.Critical ? Verdict.Critical : Verdict.High };
        result.Findings.Add(finding);
        return result;
    }
}
