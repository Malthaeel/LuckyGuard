namespace LuckyGuard.Guard;

public sealed class GuardOptions
{
    public IReadOnlyList<string> WatchRoots { get; init; } = Array.Empty<string>();
    public TimeSpan DebounceWindow { get; init; } = TimeSpan.FromMilliseconds(1500);
    public TimeSpan NetworkPollInterval { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan DuplicateAlertWindow { get; init; } = TimeSpan.FromMinutes(5);
    public int QueueCapacity { get; init; } = 4096;
    public bool MonitorNetwork { get; init; } = true;
    public bool Verbose { get; init; }

    public static GuardOptions CreateDefault(IEnumerable<string>? extraRoots = null, bool monitorNetwork = true, int networkSeconds = 30, bool verbose = false)
    {
        var roots = GuardDefaultRoots.GetDefaultRoots().ToList();
        if (extraRoots is not null)
        {
            foreach (string root in extraRoots.Where(x => !string.IsNullOrWhiteSpace(x))) roots.Add(root);
        }
        return CreateForRoots(roots, monitorNetwork, networkSeconds, verbose);
    }

    public static GuardOptions CreateForRoots(IEnumerable<string> roots, bool monitorNetwork = true, int networkSeconds = 30, bool verbose = false) => new()
    {
        WatchRoots = NormalizeRoots(roots),
        MonitorNetwork = monitorNetwork,
        NetworkPollInterval = TimeSpan.FromSeconds(Math.Clamp(networkSeconds, 5, 3600)),
        Verbose = verbose
    };

    internal static IReadOnlyList<string> NormalizeRoots(IEnumerable<string> roots)
    {
        var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in roots)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'))));
                if (Directory.Exists(full)) normalized.Add(full);
            }
            catch { }
        }
        var ordered = normalized.OrderBy(x => x.Length).ThenBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        var compact = new List<string>();
        foreach (string candidate in ordered)
        {
            bool nested = compact.Any(parent => IsSameOrChild(candidate, parent));
            if (!nested) compact.Add(candidate);
        }
        return compact.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool IsSameOrChild(string candidate, string parent)
    {
        if (candidate.Equals(parent, StringComparison.OrdinalIgnoreCase)) return true;
        string prefix = parent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}
