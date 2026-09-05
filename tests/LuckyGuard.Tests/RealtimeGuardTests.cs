using LuckyGuard.Guard;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Tests;

public sealed class RealtimeGuardTests
{
    [Fact]
    public async Task WaitForStableFile_ReturnsTrueForExistingStableFile()
    {
        string path = Path.Combine(Path.GetTempPath(), "lg-guard-" + Guid.NewGuid().ToString("N") + ".exe");
        await File.WriteAllBytesAsync(path, [0x4D, 0x5A, 0, 0]);
        try { Assert.True(await RealtimeGuard.WaitForStableFileAsync(path, CancellationToken.None)); }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task WaitForStableFile_ReturnsFalseForMissingFile()
    {
        string path = Path.Combine(Path.GetTempPath(), "missing-" + Guid.NewGuid().ToString("N") + ".exe");
        Assert.False(await RealtimeGuard.WaitForStableFileAsync(path, CancellationToken.None));
    }

    [Fact]
    public async Task TryQueue_DebouncesSamePath()
    {
        var options = new GuardOptions { WatchRoots = Array.Empty<string>(), DebounceWindow = TimeSpan.FromSeconds(2), MonitorNetwork = false };
        await using var guard = new RealtimeGuard(options, new GuardScanService(new IocStore()), _ => Task.CompletedTask);
        var now = DateTimeOffset.UtcNow;
        Assert.True(guard.TryQueue(new GuardEvent(GuardEventKind.Created, "C:\\Temp\\a.exe", now)));
        Assert.False(guard.TryQueue(new GuardEvent(GuardEventKind.Changed, "C:\\Temp\\a.exe", now.AddMilliseconds(100))));
        Assert.Equal(2, guard.Statistics.EventsObserved);
        Assert.Equal(1, guard.Statistics.EventsQueued);
        Assert.Equal(1, guard.Statistics.EventsDebounced);
    }
    [Fact]
    public async Task TryQueue_ReportsCapacityDropInsteadOfSilentlyDroppingOldest()
    {
        var options = new GuardOptions { WatchRoots = Array.Empty<string>(), QueueCapacity = 1, DebounceWindow = TimeSpan.Zero, MonitorNetwork = false };
        await using var guard = new RealtimeGuard(options, new GuardScanService(new IocStore()), _ => Task.CompletedTask);
        var now = DateTimeOffset.UtcNow;
        Assert.True(guard.TryQueue(new GuardEvent(GuardEventKind.Created, Path.Combine(Path.GetTempPath(), "lg-cap-a.exe"), now)));
        Assert.False(guard.TryQueue(new GuardEvent(GuardEventKind.Created, Path.Combine(Path.GetTempPath(), "lg-cap-b.exe"), now.AddMilliseconds(1))));
        Assert.Equal(1, guard.Statistics.QueueDrops);
        Assert.Equal(1, guard.Statistics.Errors);
    }

}
