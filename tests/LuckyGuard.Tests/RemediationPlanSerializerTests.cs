using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Remediation.Models;
using LuckyGuard.Remediation.Serialization;

namespace LuckyGuard.Tests;

public sealed class RemediationPlanSerializerTests
{
    [Fact]
    public void RoundTrip_PreservesAction()
    {
        var plan = new RemediationPlan
        {
            PlanId = "abc",
            CreatedAtUtc = DateTimeOffset.Parse("2026-09-04T00:00:00Z"),
            SourceTarget = new ScanTarget(ScanTargetKind.System, "system"),
            SourceVerdict = Verdict.High,
            SourceFindings = 1,
            Actions = [new RemediationAction
            {
                Id="1", Kind=RemediationActionKind.ReviewOnly, FindingId="X", Title="x",
                Severity=DetectionSeverity.High, Confidence=DetectionConfidence.Heuristic,
                Target="x", AutoEligible=false, RequiresElevation=false, Reason="review"
            }]
        };
        var roundTrip = RemediationPlanSerializer.Deserialize(RemediationPlanSerializer.Serialize(plan));
        Assert.Equal("abc", roundTrip.PlanId);
        Assert.Single(roundTrip.Actions);
        Assert.Equal(RemediationActionKind.ReviewOnly, roundTrip.Actions[0].Kind);
    }
}
