namespace LuckyGuard.Windows.Processes;

public sealed record ProcessSnapshot(
    int ProcessId,
    int ParentProcessId,
    string Name,
    string? ImagePath,
    string? CommandLine,
    bool? HasTrustedSignature);
