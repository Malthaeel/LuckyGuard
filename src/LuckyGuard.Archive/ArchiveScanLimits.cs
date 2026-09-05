namespace LuckyGuard.Archive;

public sealed record ArchiveScanLimits
{
    public int MaxEntries { get; init; } = 5_000;
    public long MaxDeclaredUncompressedBytes { get; init; } = 512L * 1024 * 1024;
    public long MaxEntryScanBytes { get; init; } = 64L * 1024 * 1024;
    public long MaxTextScanBytes { get; init; } = 4L * 1024 * 1024;
    public int MaxCompressionRatio { get; init; } = 200;
    public int MaxNestedDepth { get; init; } = 2;
}
