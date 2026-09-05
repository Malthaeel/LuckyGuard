using LuckyGuard.Core.Detection;

namespace LuckyGuard.Quarantine;

public sealed class QuarantineEntry
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string StoredPath { get; init; }
    public required string Sha256 { get; init; }
    public required long Size { get; init; }
    public required DateTimeOffset QuarantinedAtUtc { get; init; }
    public required DetectionSeverity Severity { get; init; }
    public required DetectionConfidence Confidence { get; init; }
    public List<string> FindingIds { get; init; } = [];
}
