namespace LuckyGuard.Core.Scanning;

public sealed class ScanCoordinator(IEnumerable<IScanner> scanners)
{
    private readonly IReadOnlyList<IScanner> _scanners = scanners.ToArray();

    public async Task<ScanResult> ScanAsync(ScanTarget target, ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult { Target = target };
        var context = new ScanContext(target, options ?? new ScanOptions(), cancellationToken);
        var applicable = _scanners.Where(s => s.CanScan(target)).ToArray();
        result.Metrics["scannersApplicable"] = applicable.Length;

        foreach (var scanner in applicable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await scanner.ScanAsync(context, result).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.Errors.Add(new ScanError(scanner.Name, ex.Message, target.Value));
            }
        }

        result.FinishedAtUtc = DateTimeOffset.UtcNow;
        return result;
    }
}
