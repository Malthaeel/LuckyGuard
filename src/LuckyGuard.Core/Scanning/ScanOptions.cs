namespace LuckyGuard.Core.Scanning;

public sealed record ScanOptions
{
    public int MaxFiles { get; init; } = 250_000;
    public long MaxFileBytes { get; init; } = 256L * 1024 * 1024;
    public bool FollowReparsePoints { get; init; } = false;
    public bool IgnoreInaccessible { get; init; } = true;
}
