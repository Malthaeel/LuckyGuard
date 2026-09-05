using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Remediation.Models;

public sealed class RemediationPlan
{
    public int SchemaVersion { get; init; } = 1;
    public required string PlanId { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required ScanTarget SourceTarget { get; init; }
    public required Verdict SourceVerdict { get; init; }
    public int SourceFindings { get; init; }
    public List<RemediationAction> Actions { get; init; } = [];
    public List<string> Notes { get; init; } = [];
}
