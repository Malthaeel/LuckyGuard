namespace LuckyGuard.Remediation.Models;

public sealed class RemediationExecutionResult
{
    public required string PlanId { get; init; }
    public required string ExecutionId { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset FinishedAtUtc { get; set; }
    public List<string> Applied { get; } = [];
    public List<string> Skipped { get; } = [];
    public List<string> Errors { get; } = [];
    public bool Success => Errors.Count == 0;
}
