namespace LuckyGuard.Core.Configuration;

public sealed class LuckyGuardConfig
{
    public int SchemaVersion { get; set; } = 1;
    public ScanConfig Scan { get; set; } = new();
    public ReportingConfig Reporting { get; set; } = new();
}

public sealed class ScanConfig
{
    public long MaxFileBytes { get; set; } = 256L * 1024 * 1024;
    public int MaxFiles { get; set; } = 250_000;
    public bool FollowReparsePoints { get; set; }
    public bool IgnoreInaccessible { get; set; } = true;
}

public sealed class ReportingConfig
{
    public string DefaultFormat { get; set; } = "text";
    public bool IncludeEvidence { get; set; } = true;
}
