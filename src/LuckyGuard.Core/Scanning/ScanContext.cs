namespace LuckyGuard.Core.Scanning;

public sealed record ScanContext(ScanTarget Target, ScanOptions Options, CancellationToken CancellationToken);
