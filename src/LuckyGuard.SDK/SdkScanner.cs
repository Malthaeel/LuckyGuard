using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.SDK.Analysis;
using LuckyGuard.SDK.Discovery;

namespace LuckyGuard.SDK;

public sealed class SdkScanner : IScanner
{
    public string Name => "SdkScanner";
    public bool CanScan(ScanTarget target) => target.Kind == ScanTargetKind.System && (target.Value.Equals("sdk", StringComparison.OrdinalIgnoreCase) || target.Value.Equals("system", StringComparison.OrdinalIgnoreCase));

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        var analyzer = new SdkSourceAnalyzer();
        var roots = SdkPathDiscovery.Discover();
        int files = 0;
        foreach (string root in roots)
        {
            foreach (string file in EnumerateFiles(root, context, result))
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                if (files >= context.Options.MaxFiles)
                {
                    result.Errors.Add(new ScanError(Name, "SDK discovery limit reached; scan coverage is incomplete."));
                    break;
                }
                try { result.Findings.AddRange(analyzer.Analyze(file, context.Options.MaxFileBytes)); files++; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError(Name, ex.Message, file)); }
            }
        }
        result.Metrics["sdkRootsDiscovered"] = roots.Count;
        result.Metrics["sdkFilesAnalyzed"] = files;
        if (roots.Count == 0) result.Notes.Add("No Windows SDK/MSVC include roots were discovered on this machine.");
        else result.Notes.Add("SDK scan is read-only; confirmed toolchain poisoning should be remediated with vendor repair/reinstall rather than in-place source patching.");
        if (roots.Count > 0 && result.Findings.Count == 0 && result.Errors.Count == 0) result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }

    private static IEnumerable<string> EnumerateFiles(string root, ScanContext context, ScanResult result)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string dir = pending.Pop();
            string[] files;
            string[] dirs;
            try { files = Directory.GetFiles(dir); dirs = Directory.GetDirectories(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("SdkScanner", ex.Message, dir));
                continue;
            }
            foreach (string f in files) yield return f;
            foreach (string child in dirs)
            {
                try
                {
                    var attr = File.GetAttributes(child);
                    if (!context.Options.FollowReparsePoints && attr.HasFlag(FileAttributes.ReparsePoint)) continue;
                    pending.Push(child);
                }
                catch { if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("SdkScanner", "Unable to inspect directory attributes.", child)); }
            }
        }
    }
}
