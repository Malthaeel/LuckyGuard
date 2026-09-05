namespace LuckyGuard.Remediation.Execution;

public sealed class RemediationJournal
{
    public required string ExecutionId { get; init; }
    public required string PlanId { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public List<string> QuarantineEntryIds { get; init; } = [];
    public List<RegistryValueBackup> RegistryBackups { get; init; } = [];
    public List<ScheduledTaskBackup> ScheduledTaskBackups { get; init; } = [];
    public List<ServiceBackup> ServiceBackups { get; init; } = [];
    public List<string> AppliedActionIds { get; init; } = [];
}
