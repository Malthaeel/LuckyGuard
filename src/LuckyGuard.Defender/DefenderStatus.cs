namespace LuckyGuard.Defender;

public sealed class DefenderStatus
{
    public bool Available { get; init; }
    public bool AntivirusEnabled { get; init; }
    public bool RealTimeProtectionEnabled { get; init; }
    public bool BehaviorMonitorEnabled { get; init; }
    public bool IoavProtectionEnabled { get; init; }
    public bool AntispywareEnabled { get; init; }
    public string? AntivirusSignatureVersion { get; init; }
    public DateTimeOffset? AntivirusSignatureLastUpdated { get; init; }
    public string? Error { get; init; }
}
