namespace LuckyGuard.Remediation.Execution;

public sealed class ServiceBackup
{
    public required string ServiceName { get; init; }
    public required string RegistryBackupFile { get; init; }
    public required string Sha256 { get; init; }
    public bool RebootMayBeRequired { get; init; } = true;
}
