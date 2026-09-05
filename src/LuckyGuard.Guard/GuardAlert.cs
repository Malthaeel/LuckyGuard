using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Guard;

public enum GuardAlertSource { FileSystem, Network, Diagnostic }

public sealed record GuardAlert(GuardAlertSource Source, DateTimeOffset ObservedAtUtc, string Subject, ScanResult? Result = null, string? Message = null);
