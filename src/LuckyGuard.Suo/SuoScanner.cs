using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Suo;

public sealed class SuoScanner : IScanner
{
    public string Name => "SuoScanner";
    public bool CanScan(ScanTarget target) => target.Kind is ScanTargetKind.Path or ScanTargetKind.Solution or ScanTargetKind.Project or ScanTargetKind.File;

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        var analyzer = new SuoFileAnalyzer();
        int analyzed = 0;
        foreach (string file in Candidates(context, result))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (analyzed >= context.Options.MaxFiles)
            {
                result.Errors.Add(new ScanError(Name, "SUO discovery limit reached; scan coverage is incomplete."));
                break;
            }
            try { result.Findings.AddRange(analyzer.Analyze(file, context.Options.MaxFileBytes)); analyzed++; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { result.Errors.Add(new ScanError(Name, ex.Message, file)); }
        }
        result.Metrics["suoFilesAnalyzed"] = analyzed;
        if (analyzed > 0 && result.Findings.Count == 0 && result.Errors.Count == 0 && result.Verdict == Verdict.NotAssessed) result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }

    private static IEnumerable<string> Candidates(ScanContext context, ScanResult result)
    {
        string target = context.Target.FullPath;
        if (File.Exists(target))
        {
            if (Path.GetExtension(target).Equals(".suo", StringComparison.OrdinalIgnoreCase)) yield return target;
            string? root = Path.GetDirectoryName(target);
            if (context.Target.Kind is ScanTargetKind.Solution or ScanTargetKind.Project && root is not null)
                foreach (string f in EnumerateSuo(root, context, result)) yield return f;
            yield break;
        }
        if (Directory.Exists(target)) foreach (string f in EnumerateSuo(target, context, result)) yield return f;
    }

    private static IEnumerable<string> EnumerateSuo(string root, ScanContext context, ScanResult result)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string dir = pending.Pop();
            string[] files;
            string[] dirs;
            try { files = Directory.GetFiles(dir, "*.suo"); dirs = Directory.GetDirectories(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("SuoScanner", ex.Message, dir));
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
                catch { if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("SuoScanner", "Unable to inspect directory attributes.", child)); }
            }
        }
    }
}
