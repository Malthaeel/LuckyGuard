using LuckyGuard.Core.Detection;

namespace LuckyGuard.Windows.Analysis;

public sealed record CommandAssessment(
    DetectionSeverity Severity,
    DetectionConfidence Confidence,
    string Reason,
    IReadOnlyList<Evidence> Evidence);
