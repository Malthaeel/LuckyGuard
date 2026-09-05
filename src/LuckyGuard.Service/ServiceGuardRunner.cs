using LuckyGuard.Guard;

namespace LuckyGuard.ServiceHost;

internal static class ServiceGuardRunner
{
    public static async Task RunAsync(CancellationToken cancellationToken, bool requireConfig = true)
    {
        GuardServiceConfig config = requireConfig ? GuardServiceConfigStore.LoadRequired() : GuardServiceConfigStore.Load();
        GuardOptions options = config.ToOptions();
        if (options.WatchRoots.Count == 0 && !options.MonitorNetwork)
            throw new InvalidDataException("Guard service has no available watch roots and network monitoring is disabled.");
        GuardScanService scanService = GuardScanService.CreateDefault(out string? iocError);
        var logger = new GuardJsonlLogger(GuardServiceConfigStore.LogPath);
        if (!string.IsNullOrWhiteSpace(iocError))
            AppendDiagnostic($"IOC feed warning: {iocError}");

        await using var guard = new RealtimeGuard(options, scanService, alert =>
        {
            logger.Write(alert);
            return Task.CompletedTask;
        });
        await guard.RunAsync(cancellationToken);
        AppendDiagnostic($"Guard stopped. Events={guard.Statistics.EventsObserved}, scans={guard.Statistics.FilesScanned}, network={guard.Statistics.NetworkPolls}, alerts={guard.Statistics.Alerts}, errors={guard.Statistics.Errors}, overflows={guard.Statistics.WatcherOverflows}, queueDrops={guard.Statistics.QueueDrops}");
    }

    public static void AppendDiagnostic(string message)
    {
        try
        {
            Directory.CreateDirectory(GuardServiceConfigStore.DirectoryPath);
            File.AppendAllText(GuardServiceConfigStore.DiagnosticLogPath, $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
        }
        catch { }
    }
}
