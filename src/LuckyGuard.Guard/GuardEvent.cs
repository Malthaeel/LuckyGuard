namespace LuckyGuard.Guard;

public enum GuardEventKind { Created, Changed, Renamed }

public sealed record GuardEvent(GuardEventKind Kind, string Path, DateTimeOffset ObservedAtUtc);
