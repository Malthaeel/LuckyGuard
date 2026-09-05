using LuckyGuard.Core.Detection;

namespace LuckyGuard.Core.Scanning;

public sealed class BaselineTargetScanner : IScanner
{
    public string Name => "BaselineTargetScanner";

    public bool CanScan(ScanTarget target) => target.Kind is ScanTargetKind.Path or ScanTargetKind.Solution or ScanTargetKind.Project or ScanTargetKind.File;

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        string path = context.Target.FullPath;
        bool isDirectory = Directory.Exists(path);
        bool isFile = File.Exists(path);
        if (!isDirectory && !isFile)
        {
            result.Errors.Add(new ScanError(Name, "Target does not exist.", path));
            result.Verdict = Verdict.Incomplete;
            return Task.CompletedTask;
        }

        if (context.Target.Kind == ScanTargetKind.Solution && (!isFile || !(path.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase))))
        {
            result.Errors.Add(new ScanError(Name, "Solution target must be an existing .sln or .slnx file.", path));
            result.Verdict = Verdict.Incomplete;
            return Task.CompletedTask;
        }

        result.Metrics["targetExists"] = 1;
        result.Metrics["targetIsDirectory"] = isDirectory ? 1 : 0;
        if (isFile) result.Metrics["targetBytes"] = new FileInfo(path).Length;
        result.Notes.Add("Baseline target validation passed.");
        if (context.Target.Kind == ScanTargetKind.Project && (!isFile || !new[] { ".vcxproj", ".csproj", ".fsproj", ".vbproj" }.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase)))
        {
            result.Errors.Add(new ScanError(Name, "Project target must be an existing supported MSBuild project file.", path));
            result.Verdict = Verdict.Incomplete;
            return Task.CompletedTask;
        }

        result.Verdict = Verdict.NotAssessed;
        return Task.CompletedTask;
    }
}
