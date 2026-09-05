using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.PE.Analysis;

namespace LuckyGuard.PE;

public sealed class PeScanner : IScanner
{
    public string Name => "PeScanner";
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".scr", ".cpl" };

    public bool CanScan(ScanTarget target) => target.Kind is ScanTargetKind.Path or ScanTargetKind.Solution or ScanTargetKind.Project or ScanTargetKind.File;

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        var analyzer = new PeFileAnalyzer();
        int analyzed = 0;
        int visited = 0;
        foreach (string file in EnumerateCandidates(context, result))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (++visited > context.Options.MaxFiles)
            {
                result.Errors.Add(new ScanError(Name, "PE discovery limit reached; scan coverage is incomplete."));
                break;
            }
            try
            {
                result.Findings.AddRange(analyzer.Analyze(file, context.Options.MaxFileBytes));
                analyzed++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                result.Errors.Add(new ScanError(Name, ex.Message, file));
            }
        }
        result.Metrics["peFilesAnalyzed"] = analyzed;
        if (analyzed > 0 && result.Findings.Count == 0 && result.Errors.Count == 0 && result.Verdict == Verdict.NotAssessed) result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }

    private static IEnumerable<string> EnumerateCandidates(ScanContext context, ScanResult result)
    {
        string target = context.Target.FullPath;
        if (File.Exists(target))
        {
            if (Extensions.Contains(Path.GetExtension(target))) yield return target;
            if (context.Target.Kind is ScanTargetKind.Solution or ScanTargetKind.Project)
            {
                string? dir = Path.GetDirectoryName(target);
                if (!string.IsNullOrWhiteSpace(dir))
                    foreach (var file in EnumerateDirectory(dir, context, result)) yield return file;
            }
            yield break;
        }
        if (Directory.Exists(target))
            foreach (var file in EnumerateDirectory(target, context, result)) yield return file;
    }

    private static IEnumerable<string> EnumerateDirectory(string root, ScanContext context, ScanResult result)
    {
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.Count > 0)
        {
            string dir = pending.Pop();
            IEnumerable<string> files;
            IEnumerable<string> dirs;
            try { files = Directory.EnumerateFiles(dir); dirs = Directory.EnumerateDirectories(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("PeScanner", ex.Message, dir));
                continue;
            }
            foreach (string file in files) if (Extensions.Contains(Path.GetExtension(file))) yield return file;
            foreach (string child in dirs)
            {
                try
                {
                    var attr = File.GetAttributes(child);
                    if (!context.Options.FollowReparsePoints && attr.HasFlag(FileAttributes.ReparsePoint)) continue;
                    pending.Push(child);
                }
                catch { if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("PeScanner", "Unable to inspect directory attributes.", child)); }
            }
        }
    }
}
