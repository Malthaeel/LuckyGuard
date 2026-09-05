using LuckyGuard.Core.Detection;

namespace LuckyGuard.Remediation.Models;

public sealed class RemediationAction
{
    public required string Id { get; init; }
    public required RemediationActionKind Kind { get; init; }
    public required string FindingId { get; init; }
    public required string Title { get; init; }
    public required DetectionSeverity Severity { get; init; }
    public required DetectionConfidence Confidence { get; init; }
    public required string Target { get; init; }
    public string? ValueName { get; init; }
    public string? RegistryView { get; init; }
    public bool AutoEligible { get; init; }
    public bool RequiresElevation { get; init; }
    public required string Reason { get; init; }
}
