namespace LuckyGuard.Ioc.Feed;

public sealed class IocUpdateResult
{
    public required string FeedVersion { get; init; }
    public required int Entries { get; init; }
    public required string FeedPath { get; init; }
    public required string SignaturePath { get; init; }
    public required DateTimeOffset UpdatedAtUtc { get; init; }
}
