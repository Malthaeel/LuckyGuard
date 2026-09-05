namespace LuckyGuard.Core.Scanning;

public sealed record ScanError(string Scanner, string Message, string? Path = null);
