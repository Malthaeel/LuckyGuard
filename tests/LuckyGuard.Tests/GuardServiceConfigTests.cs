using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardServiceConfigTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
    public GuardServiceConfigTests() => Directory.CreateDirectory(_root);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    [Fact]
    public void ToOptions_UsesConfiguredRootsWithoutServiceAccountDefaults()
    {
        string watched = Path.Combine(_root, "watch");
        Directory.CreateDirectory(watched);
        var config = new GuardServiceConfig { WatchRoots = [watched], MonitorNetwork = false, NetworkPollSeconds = 17 };
        GuardOptions options = config.ToOptions();
        Assert.Single(options.WatchRoots);
        Assert.Equal(Path.GetFullPath(watched), options.WatchRoots[0]);
        Assert.False(options.MonitorNetwork);
        Assert.Equal(17, options.NetworkPollInterval.TotalSeconds);
    }

    [Fact]
    public void CreateForRoots_ClampsNetworkInterval()
    {
        GuardOptions low = GuardOptions.CreateForRoots([_root], networkSeconds: 1);
        GuardOptions high = GuardOptions.CreateForRoots([_root], networkSeconds: 99999);
        Assert.Equal(5, low.NetworkPollInterval.TotalSeconds);
        Assert.Equal(3600, high.NetworkPollInterval.TotalSeconds);
    }
}
