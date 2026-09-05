using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.MSBuild.Analysis;
using LuckyGuard.Solution;
using LuckyGuard.Source;

namespace LuckyGuard.Guard;

public sealed class GuardFocusedDeveloperScanner : IScanner
{
    public string Name => "GuardFocusedDeveloperScanner";
    public bool CanScan(ScanTarget target) => target.Kind == ScanTargetKind.File && GuardFileClassifier.IsDeveloperSurface(target.Value);

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        string file = context.Target.FullPath;
        if (!File.Exists(file)) return Task.CompletedTask;
        string ext = Path.GetExtension(file);
        string name = Path.GetFileName(file);
        int assessed = 0;

        try
        {
            if (DeveloperFileKinds.SourceExtensions.Contains(ext))
            {
                result.Findings.AddRange(new SourceFileAnalyzer().Analyze(file, context.Options.MaxFileBytes));
                result.Metrics["guardSourceFilesAnalyzed"] = 1;
                assessed++;
            }
            else if (name.Equals("Directory.Build.rsp", StringComparison.OrdinalIgnoreCase) || ext.Equals(".rsp", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.AddRange(new RspFileAnalyzer().Analyze(file, context.Options.MaxFileBytes));
                result.Metrics["guardRspFilesAnalyzed"] = 1;
                assessed++;
            }
            else if (IsMsBuildFile(file))
            {
                string scope = Path.GetDirectoryName(file) ?? Directory.GetCurrentDirectory();
                var msbuild = new MsBuildFileAnalyzer().Analyze([file], scope);
                result.Findings.AddRange(msbuild.Findings);
                foreach (var error in msbuild.Errors) result.Errors.Add(new ScanError("GuardMsBuildFileAnalyzer", error.Message, error.Path));
                result.Metrics["guardMsbuildFilesAnalyzed"] = msbuild.FilesAnalyzed.Count;
                result.Metrics["guardMsbuildImportsFollowed"] = msbuild.ImportsFollowed;
                assessed++;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            result.Errors.Add(new ScanError(Name, ex.Message, file));
        }

        if (assessed > 0 && result.Findings.Count == 0 && result.Errors.Count == 0 && result.Verdict == Verdict.NotAssessed)
            result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }

    private static bool IsMsBuildFile(string path)
    {
        string ext = Path.GetExtension(path);
        string name = Path.GetFileName(path);
        return DeveloperFileKinds.MsBuildExtensions.Contains(ext)
            || name.Equals("Directory.Build.props", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Build.targets", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Solution.props", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Solution.targets", StringComparison.OrdinalIgnoreCase)
            || (name.StartsWith("before.", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".targets", StringComparison.OrdinalIgnoreCase))
            || (name.StartsWith("after.", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".targets", StringComparison.OrdinalIgnoreCase));
    }
}
