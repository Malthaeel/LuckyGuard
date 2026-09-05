namespace LuckyGuard.Remediation.Execution;

public sealed class RegistryValueBackup
{
    public required string Hive { get; init; }
    public required string SubKey { get; init; }
    public required string ValueName { get; init; }
    public required string View { get; init; }
    public required string Kind { get; init; }
    public string? StringValue { get; init; }
    public string[]? StringArrayValue { get; init; }
    public byte[]? BinaryValue { get; init; }
    public long? IntegerValue { get; init; }
}
