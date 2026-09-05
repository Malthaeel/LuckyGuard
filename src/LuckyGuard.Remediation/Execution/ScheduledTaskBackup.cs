namespace LuckyGuard.Remediation.Execution;

public sealed class ScheduledTaskBackup
{
    public required string TaskPath { get; init; }
    public required string XmlBackupFile { get; init; }
    public required string Sha256 { get; init; }
}
