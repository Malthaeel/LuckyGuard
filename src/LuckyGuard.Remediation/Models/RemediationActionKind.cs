namespace LuckyGuard.Remediation.Models;

public enum RemediationActionKind
{
    ReviewOnly,
    QuarantineFile,
    DeleteRegistryValue,
    DeleteScheduledTask,
    DeleteService
}
