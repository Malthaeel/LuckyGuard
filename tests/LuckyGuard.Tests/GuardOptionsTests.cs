using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardOptionsTests
{
    [Fact]
    public void NormalizeRoots_RemovesNestedDuplicateRoots()
    {
        string root = Path.Combine(Path.GetTempPath(), "lg-guard-root-" + Guid.NewGuid().ToString("N"));
        string child = Path.Combine(root, "child");
        Directory.CreateDirectory(child);
        try
        {
            var roots = GuardOptions.NormalizeRoots([root, child, root]);
            Assert.Single(roots);
            Assert.Equal(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar), roots[0], StringComparer.OrdinalIgnoreCase);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void CreateDefault_ClampsNetworkInterval()
    {
        var options = GuardOptions.CreateDefault(networkSeconds: 1);
        Assert.Equal(TimeSpan.FromSeconds(5), options.NetworkPollInterval);
    }
}
