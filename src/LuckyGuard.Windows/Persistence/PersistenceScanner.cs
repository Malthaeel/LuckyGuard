using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Windows.Persistence;

public sealed class PersistenceScanner : IScanner
{
    public string Name => "PersistenceScanner";
    public bool CanScan(ScanTarget target) => target.Kind == ScanTargetKind.System && (target.Value.Equals("persistence", StringComparison.OrdinalIgnoreCase) || target.Value.Equals("system", StringComparison.OrdinalIgnoreCase));

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        if (!OperatingSystem.IsWindows())
        {
            result.Notes.Add("Persistence scanner is Windows-only.");
            return Task.CompletedTask;
        }

        RegistryPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        StartupPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        ScheduledTaskPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        ServicePersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        IfeoPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        WinlogonPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        AppInitPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);
        WmiPersistenceScanner.Scan(result, context.Options.IgnoreInaccessible);

        result.Notes.Add("Persistence scanning is read-only. Remediation is a separate, confirmation-gated workflow; scan commands never remove entries.");
        if (result.Findings.Count == 0 && result.Errors.Count == 0) result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }
}
