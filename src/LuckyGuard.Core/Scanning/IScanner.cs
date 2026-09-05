namespace LuckyGuard.Core.Scanning;

public interface IScanner
{
    string Name { get; }
    bool CanScan(ScanTarget target);
    Task ScanAsync(ScanContext context, ScanResult result);
}
