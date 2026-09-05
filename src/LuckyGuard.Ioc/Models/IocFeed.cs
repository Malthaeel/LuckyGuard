namespace LuckyGuard.Ioc.Models;

public sealed class IocFeed
{
    public int SchemaVersion { get; set; } = 1;
    public string FeedVersion { get; set; } = "phase0-empty";
    public DateTimeOffset GeneratedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public List<IocEntry> Entries { get; set; } = [];
}
