using LuckyGuard.Core.Detection;

namespace LuckyGuard.Ioc.Models;

public sealed record IocEntry(
    string Id,
    IocType Type,
    string Value,
    DetectionConfidence Confidence,
    string Source,
    DateTimeOffset? FirstSeen = null,
    DateTimeOffset? LastVerified = null,
    string? Notes = null);
