using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.MSBuild.Analysis;
using LuckyGuard.MSBuild.Discovery;
using LuckyGuard.Solution.Discovery;
using LuckyGuard.Solution.Models;
using LuckyGuard.Solution.Parsing;
using LuckyGuard.Source;

namespace LuckyGuard.Solution.Scanning;

public sealed class DeveloperProjectScanner : IScanner
{
    public string Name => "DeveloperProjectScanner";

    public bool CanScan(ScanTarget target) => target.Kind is ScanTargetKind.Path or ScanTargetKind.Solution or ScanTargetKind.Project;

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        string target = context.Target.FullPath;
        if ((context.Target.Kind == ScanTargetKind.Path && !Directory.Exists(target)) || (context.Target.Kind != ScanTargetKind.Path && !File.Exists(target))) return Task.CompletedTask;

        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string scopeRoot;

        if (context.Target.Kind == ScanTargetKind.Solution)
        {
            scopeRoot = Path.GetDirectoryName(target) ?? Directory.GetCurrentDirectory();
            AddSolution(target, discovered, result);
            var discovery = new DeveloperFileDiscovery();
            AddDiscovery(discovery.Discover(scopeRoot, context.Options.MaxFiles, context.CancellationToken), discovered, result);
        }
        else if (context.Target.Kind == ScanTargetKind.Project)
        {
            scopeRoot = Path.GetDirectoryName(target) ?? Directory.GetCurrentDirectory();
            discovered.Add(target);
            var discovery = new DeveloperFileDiscovery();
            AddDiscovery(discovery.Discover(scopeRoot, context.Options.MaxFiles, context.CancellationToken), discovered, result);
        }
        else
        {
            scopeRoot = target;
            var discovery = new DeveloperFileDiscovery();
            AddDiscovery(discovery.Discover(target, context.Options.MaxFiles, context.CancellationToken), discovered, result);
            foreach (string solution in discovered.Where(x => DeveloperFileKinds.SolutionExtensions.Contains(Path.GetExtension(x))).ToArray()) AddSolution(solution, discovered, result);
        }

        foreach (string parentBuild in ParentBuildFileDiscovery.Discover(scopeRoot)) discovered.Add(parentBuild);

        var msbuildRoots = discovered.Where(IsMsBuildFile).ToArray();
        var msbuild = new MsBuildFileAnalyzer().Analyze(msbuildRoots, scopeRoot);
        result.Findings.AddRange(msbuild.Findings);
        foreach (var error in msbuild.Errors) result.Errors.Add(new ScanError("MsBuildFileAnalyzer", error.Message, error.Path));

        var rspAnalyzer = new RspFileAnalyzer();
        int rspCount = 0;
        foreach (string rsp in discovered.Where(x => Path.GetFileName(x).Equals("Directory.Build.rsp", StringComparison.OrdinalIgnoreCase)))
        {
            result.Findings.AddRange(rspAnalyzer.Analyze(rsp, context.Options.MaxFileBytes));
            rspCount++;
        }

        var source = new SourceFileAnalyzer();
        int sourceCount = 0;
        foreach (string file in discovered.Where(x => DeveloperFileKinds.SourceExtensions.Contains(Path.GetExtension(x))))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            result.Findings.AddRange(source.Analyze(file, context.Options.MaxFileBytes));
            sourceCount++;
        }

        result.Metrics["developerFilesDiscovered"] = discovered.Count;
        result.Metrics["msbuildFilesAnalyzed"] = msbuild.FilesAnalyzed.Count;
        result.Metrics["msbuildImportsFollowed"] = msbuild.ImportsFollowed;
        result.Metrics["rspFilesAnalyzed"] = rspCount;
        result.Metrics["sourceFilesAnalyzed"] = sourceCount;

        bool assessed = msbuild.FilesAnalyzed.Count > 0 || rspCount > 0 || sourceCount > 0 || discovered.Any(x => DeveloperFileKinds.SolutionExtensions.Contains(Path.GetExtension(x)));
        if (assessed && result.Errors.Count == 0 && result.Findings.Count == 0) result.Verdict = Verdict.Clean;
        result.Notes.Add("Developer-project scan covers supported solution/MSBuild/source surfaces only; CLEAN here is not a full Windows-system verdict.");
        return Task.CompletedTask;
    }

    private static void AddDiscovery(DeveloperDiscoveryResult discovery, HashSet<string> discovered, ScanResult result)
    {
        foreach (string file in discovery.Files) discovered.Add(file);
        result.Metrics.TryGetValue("filesystemEntriesVisited", out long currentEntries);
        result.Metrics["filesystemEntriesVisited"] = currentEntries + discovery.EntriesVisited;
        if (discovery.LimitReached)
            result.Errors.Add(new ScanError("DeveloperFileDiscovery", "Discovery limit reached; scan coverage is incomplete."));
    }

    private static void AddSolution(string solutionPath, HashSet<string> discovered, ScanResult result)
    {
        discovered.Add(solutionPath);
        try
        {
            ParsedSolution parsed = Path.GetExtension(solutionPath).Equals(".slnx", StringComparison.OrdinalIgnoreCase) ? SlnxParser.Parse(solutionPath) : SlnParser.Parse(solutionPath);
            foreach (var project in parsed.Projects)
            {
                if (File.Exists(project.Path)) discovered.Add(project.Path);
                else result.Errors.Add(new ScanError("SolutionParser", "Referenced project does not exist.", project.Path));
            }
            result.Metrics.TryGetValue("solutionProjects", out long currentProjects);
            result.Metrics["solutionProjects"] = currentProjects + parsed.Projects.Count;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            result.Errors.Add(new ScanError("SolutionParser", ex.Message, solutionPath));
        }
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
            || name.StartsWith("before.", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".targets", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("after.", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".targets", StringComparison.OrdinalIgnoreCase);
    }
}
