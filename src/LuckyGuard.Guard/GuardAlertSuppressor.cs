using LuckyGuard.Core.Detection;

namespace LuckyGuard.Guard;

public sealed class GuardAlertSuppressor(TimeSpan window)
{
    private readonly Dictionary<string, DateTimeOffset> _lastSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();

    public bool ShouldEmit(GuardAlert alert, DateTimeOffset now)
    {
        string key = Fingerprint(alert);
        lock (_sync)
        {
            if (_lastSeen.TryGetValue(key, out var previous) && now - previous < window) return false;
            _lastSeen[key] = now;
            if (_lastSeen.Count > 4096)
            {
                foreach (string stale in _lastSeen.Where(x => now - x.Value >= window).Select(x => x.Key).ToArray()) _lastSeen.Remove(stale);
            }
            return true;
        }
    }

    internal static string Fingerprint(GuardAlert alert)
    {
        if (alert.Result is null) return $"{alert.Source}|{alert.Subject}|{alert.Message}";
        IEnumerable<string> findings = alert.Result.Findings
            .OrderBy(f => f.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.AffectedPath, StringComparer.OrdinalIgnoreCase)
            .Select(FindingFingerprint);
        return $"{alert.Source}|{alert.Subject}|{string.Join(";", findings)}";
    }

    private static string FindingFingerprint(DetectionFinding finding)
    {
        string evidence = string.Join(",", finding.Evidence?.Select(e => $"{e.Kind}={e.Value}").OrderBy(x => x, StringComparer.OrdinalIgnoreCase) ?? Enumerable.Empty<string>());
        return $"{finding.Id}|{finding.AffectedPath}|{finding.Severity}|{finding.Confidence}|{evidence}";
    }
}
