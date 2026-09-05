namespace LuckyGuard.Core.Detection;

public sealed record DetectionFinding(
    string Id,
    string Title,
    DetectionCategory Category,
    DetectionSeverity Severity,
    DetectionConfidence Confidence,
    string Description,
    string? AffectedPath = null,
    IReadOnlyList<Evidence>? Evidence = null);
