namespace LuckyGuard.Solution.Discovery;

public sealed class DeveloperDiscoveryResult
{
    public List<string> Files { get; } = [];
    public int EntriesVisited { get; set; }
    public bool LimitReached { get; set; }
}
