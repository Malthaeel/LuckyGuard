namespace LuckyGuard.Guard;

public static class GuardFileClassifier
{
    private static readonly HashSet<string> WatchedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".com", ".msi",
        ".bat", ".cmd", ".ps1", ".js", ".vbs", ".zip", ".jar", ".nupkg", ".rar", ".7z",
        ".sln", ".slnx", ".vcxproj", ".csproj", ".fsproj", ".vbproj",
        ".props", ".targets", ".user", ".suo", ".rsp",
        ".cpp", ".cc", ".c", ".h", ".hpp"
    };

    private static readonly HashSet<string> WatchedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Directory.Build.props", "Directory.Build.targets", "Directory.Build.rsp",
        "Directory.Solution.props", "Directory.Solution.targets"
    };

    public static bool ShouldInspect(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || GuardInternalPaths.IsInternalPath(path)) return false;
        string fileName;
        try { fileName = Path.GetFileName(path); }
        catch { return false; }
        if (WatchedNames.Contains(fileName)) return true;
        return WatchedExtensions.Contains(Path.GetExtension(fileName));
    }

    public static bool IsDeveloperSurface(string path)
    {
        string fileName = Path.GetFileName(path);
        string ext = Path.GetExtension(fileName);
        return WatchedNames.Contains(fileName)
            || LuckyGuard.Solution.DeveloperFileKinds.SolutionExtensions.Contains(ext)
            || LuckyGuard.Solution.DeveloperFileKinds.ProjectExtensions.Contains(ext)
            || LuckyGuard.Solution.DeveloperFileKinds.MsBuildExtensions.Contains(ext)
            || LuckyGuard.Solution.DeveloperFileKinds.SourceExtensions.Contains(ext)
            || ext.Equals(".rsp", StringComparison.OrdinalIgnoreCase);
    }

    public static IReadOnlyCollection<string> Extensions => WatchedExtensions;
}
