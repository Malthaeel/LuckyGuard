using LuckyGuard.Archive;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Detection.Scoring;
using LuckyGuard.Ioc.Feed;
using LuckyGuard.Ioc.Scanning;
using LuckyGuard.Ioc.Store;
using LuckyGuard.PE;
using LuckyGuard.Solution.Scanning;
using LuckyGuard.Suo;
using LuckyGuard.Windows.Network;

namespace LuckyGuard.Guard;

public sealed class GuardScanService
{
    private readonly IocStore _store;
    private readonly string? _feedVersion;

    public GuardScanService(IocStore store, string? feedVersion = null)
    {
        _store = store;
        _feedVersion = feedVersion;
    }

    public static GuardScanService CreateDefault(out string? error)
    {
        error = null;
        try
        {
            var paths = IocFeedLoader.LocateDefault();
            if (paths is null) { error = "IOC feed files were not found."; return new GuardScanService(new IocStore()); }
            var verified = IocFeedLoader.LoadVerified(paths.Value.Feed, paths.Value.Signature, paths.Value.PublicKey);
            return new GuardScanService(verified.Store, verified.Feed.FeedVersion);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return new GuardScanService(new IocStore());
        }
    }

    public async Task<ScanResult> ScanFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ScanTarget target = ChooseTarget(path);
        var scanners = new List<IScanner>
        {
            new BaselineTargetScanner(),
            new DeveloperProjectScanner(),
            new GuardFocusedDeveloperScanner(),
            new PeScanner(),
            new SuoScanner(),
            new ArchiveScanner(_store, _feedVersion, reportOpaqueSummary: false)
        };
        if (_store.Count > 0) scanners.Add(new FileIocScanner(_store, _feedVersion));

        var options = new ScanOptions { MaxFiles = GuardFileClassifier.IsDeveloperSurface(path) ? 25_000 : 2_000 };
        ScanResult result = await new ScanCoordinator(scanners).ScanAsync(target, options, cancellationToken);
        if (_store.Count == 0) result.Notes.Add("Realtime Guard IOC coverage is incomplete because no verified IOC feed is loaded.");
        result.Verdict = VerdictResolver.Resolve(result);
        return result;
    }

    public async Task<ScanResult> ScanNetworkAsync(CancellationToken cancellationToken = default)
    {
        var target = new ScanTarget(ScanTargetKind.System, "network");
        var scanners = new List<IScanner>();
        if (_store.Count > 0) scanners.Add(new NetworkScanner(_store, _feedVersion));
        var result = scanners.Count == 0
            ? new ScanResult { Target = target }
            : await new ScanCoordinator(scanners).ScanAsync(target, cancellationToken: cancellationToken);
        if (_store.Count == 0)
        {
            result.Errors.Add(new ScanError("RealtimeGuard", "Verified IOC feed is unavailable; network monitoring cannot be assessed."));
        }
        result.Verdict = VerdictResolver.Resolve(result);
        return result;
    }

    private static ScanTarget ChooseTarget(string path)
    {
        string ext = Path.GetExtension(path);
        if (ext.Equals(".sln", StringComparison.OrdinalIgnoreCase) || ext.Equals(".slnx", StringComparison.OrdinalIgnoreCase))
            return new ScanTarget(ScanTargetKind.Solution, path);
        if (LuckyGuard.Solution.DeveloperFileKinds.ProjectExtensions.Contains(ext))
            return new ScanTarget(ScanTargetKind.Project, path);
        return new ScanTarget(ScanTargetKind.File, path);
    }
}
