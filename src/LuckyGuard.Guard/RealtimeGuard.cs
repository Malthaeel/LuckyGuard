using System.Collections.Concurrent;
using System.Threading.Channels;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Guard;

public sealed class RealtimeGuard : IAsyncDisposable
{
    private readonly GuardOptions _options;
    private readonly GuardScanService _scanService;
    private readonly Func<GuardAlert, Task> _alertSink;
    private readonly Channel<GuardEvent> _queue;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastQueued = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly GuardAlertSuppressor _suppressor;
    private bool _started;

    public GuardStatistics Statistics { get; } = new();

    public RealtimeGuard(GuardOptions options, GuardScanService scanService, Func<GuardAlert, Task> alertSink)
    {
        _options = options;
        _scanService = scanService;
        _alertSink = alertSink;
        _suppressor = new GuardAlertSuppressor(options.DuplicateAlertWindow);
        _queue = Channel.CreateBounded<GuardEvent>(new BoundedChannelOptions(options.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (_started) throw new InvalidOperationException("Realtime Guard is already running.");
        _started = true;
        StartWatchers();

        var tasks = new List<Task> { ProcessQueueAsync(cancellationToken) };
        if (_options.MonitorNetwork) tasks.Add(NetworkLoopAsync(cancellationToken));
        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally { StopWatchers(); }
    }

    internal bool TryQueue(GuardEvent evt)
    {
        Statistics.Observe();
        if (!GuardFileClassifier.ShouldInspect(evt.Path)) return false;

        DateTimeOffset now = evt.ObservedAtUtc;
        if (_lastQueued.TryGetValue(evt.Path, out var previous) && now - previous < _options.DebounceWindow)
        {
            Statistics.Debounce();
            return false;
        }
        _lastQueued[evt.Path] = now;
        bool written = _queue.Writer.TryWrite(evt);
        if (written)
        {
            Statistics.Queue();
            return true;
        }

        Statistics.QueueDrop();
        Statistics.Error();
        _ = EmitAsync(new GuardAlert(GuardAlertSource.Diagnostic, DateTimeOffset.UtcNow, evt.Path,
            Message: "Realtime Guard event queue is full; this file event was not queued. Run a manual scan of the affected root to restore coverage confidence."));
        return false;
    }

    private void StartWatchers()
    {
        foreach (string root in _options.WatchRoots)
        {
            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                    EnableRaisingEvents = false
                };
                watcher.Created += (_, e) => TryQueue(new GuardEvent(GuardEventKind.Created, e.FullPath, DateTimeOffset.UtcNow));
                watcher.Changed += (_, e) => TryQueue(new GuardEvent(GuardEventKind.Changed, e.FullPath, DateTimeOffset.UtcNow));
                watcher.Renamed += (_, e) => TryQueue(new GuardEvent(GuardEventKind.Renamed, e.FullPath, DateTimeOffset.UtcNow));
                watcher.Error += (_, e) => _ = OnWatcherErrorAsync(root, e.GetException());
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                Statistics.Error();
                _ = EmitAsync(new GuardAlert(GuardAlertSource.Diagnostic, DateTimeOffset.UtcNow, root, Message: $"Watcher could not start: {ex.Message}"));
            }
        }
    }

    private async Task ProcessQueueAsync(CancellationToken cancellationToken)
    {
        await foreach (GuardEvent evt in _queue.Reader.ReadAllAsync(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (!await WaitForStableFileAsync(evt.Path, cancellationToken)) continue;
                Statistics.FileScan();
                ScanResult result = await _scanService.ScanFileAsync(evt.Path, cancellationToken);
                if (result.Findings.Count > 0 || result.Errors.Count > 0 || _options.Verbose)
                {
                    await EmitAsync(new GuardAlert(GuardAlertSource.FileSystem, DateTimeOffset.UtcNow, evt.Path, result));
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                Statistics.Error();
                await EmitAsync(new GuardAlert(GuardAlertSource.Diagnostic, DateTimeOffset.UtcNow, evt.Path, Message: $"Realtime file scan failed: {ex.Message}"));
            }
        }
    }

    private async Task NetworkLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                Statistics.NetworkPoll();
                ScanResult result = await _scanService.ScanNetworkAsync(cancellationToken);
                if (result.Findings.Count > 0 || result.Errors.Count > 0 || _options.Verbose)
                    await EmitAsync(new GuardAlert(GuardAlertSource.Network, DateTimeOffset.UtcNow, "active TCP/DNS state", result));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                Statistics.Error();
                await EmitAsync(new GuardAlert(GuardAlertSource.Diagnostic, DateTimeOffset.UtcNow, "network", Message: $"Realtime network scan failed: {ex.Message}"));
            }

            try { await Task.Delay(_options.NetworkPollInterval, cancellationToken); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
        }
    }

    private async Task EmitAsync(GuardAlert alert)
    {
        if (!_suppressor.ShouldEmit(alert, DateTimeOffset.UtcNow)) return;
        Statistics.Alert();
        await _alertSink(alert);
    }

    private async Task OnWatcherErrorAsync(string root, Exception? exception)
    {
        Statistics.Overflow();
        Statistics.Error();
        await EmitAsync(new GuardAlert(GuardAlertSource.Diagnostic, DateTimeOffset.UtcNow, root,
            Message: $"FileSystemWatcher reported an error/possible buffer overflow: {exception?.Message ?? "unknown error"}. Run a manual LuckyGuard scan for this root to restore coverage confidence."));
    }

    internal static async Task<bool> WaitForStableFileAsync(string path, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 6; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(path)) return false;
            try
            {
                long first = new FileInfo(path).Length;
                await Task.Delay(150, cancellationToken);
                if (!File.Exists(path)) return false;
                long second = new FileInfo(path).Length;
                if (first == second)
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    return true;
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { return false; }
            await Task.Delay(150, cancellationToken);
        }
        return File.Exists(path);
    }

    private void StopWatchers()
    {
        foreach (var watcher in _watchers)
        {
            try { watcher.EnableRaisingEvents = false; watcher.Dispose(); } catch { }
        }
        _watchers.Clear();
        _queue.Writer.TryComplete();
    }

    public ValueTask DisposeAsync()
    {
        StopWatchers();
        return ValueTask.CompletedTask;
    }
}
