namespace LuckyGuard.Guard;

public sealed class GuardStatistics
{
    private long _eventsObserved, _eventsQueued, _eventsDebounced, _filesScanned, _networkPolls, _alerts, _errors, _watcherOverflows, _queueDrops;

    public long EventsObserved => Interlocked.Read(ref _eventsObserved);
    public long EventsQueued => Interlocked.Read(ref _eventsQueued);
    public long EventsDebounced => Interlocked.Read(ref _eventsDebounced);
    public long FilesScanned => Interlocked.Read(ref _filesScanned);
    public long NetworkPolls => Interlocked.Read(ref _networkPolls);
    public long Alerts => Interlocked.Read(ref _alerts);
    public long Errors => Interlocked.Read(ref _errors);
    public long WatcherOverflows => Interlocked.Read(ref _watcherOverflows);
    public long QueueDrops => Interlocked.Read(ref _queueDrops);

    internal void Observe() => Interlocked.Increment(ref _eventsObserved);
    internal void Queue() => Interlocked.Increment(ref _eventsQueued);
    internal void Debounce() => Interlocked.Increment(ref _eventsDebounced);
    internal void FileScan() => Interlocked.Increment(ref _filesScanned);
    internal void NetworkPoll() => Interlocked.Increment(ref _networkPolls);
    internal void Alert() => Interlocked.Increment(ref _alerts);
    internal void Error() => Interlocked.Increment(ref _errors);
    internal void Overflow() => Interlocked.Increment(ref _watcherOverflows);
    internal void QueueDrop() => Interlocked.Increment(ref _queueDrops);
}
