using LuckyGuard.Core.Detection;

namespace LuckyGuard.Core.Scanning;

public sealed class ScanResult
{
    public required ScanTarget Target { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset FinishedAtUtc { get; set; }
    public Verdict Verdict { get; set; } = Verdict.NotAssessed;
    public List<DetectionFinding> Findings { get; } = [];
    public List<ScanError> Errors { get; } = [];
    public Dictionary<string, long> Metrics { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Notes { get; } = [];
}
