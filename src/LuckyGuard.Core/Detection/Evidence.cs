namespace LuckyGuard.Core.Detection;

public sealed record Evidence(string Kind, string Value, string? Source = null);
