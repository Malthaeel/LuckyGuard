namespace LuckyGuard.Solution.Discovery;

public sealed class DeveloperFileDiscovery
{
    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".svn", ".hg", "bin", "obj", "node_modules", "packages", ".vs"
    };

    public DeveloperDiscoveryResult Discover(string rootPath, int maxEntries, CancellationToken cancellationToken)
    {
        string root = Path.GetFullPath(rootPath);
        var result = new DeveloperDiscoveryResult();
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0 && result.EntriesVisited < maxEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string current = pending.Pop();
            IEnumerable<string> dirs;
            IEnumerable<string> files;
            try
            {
                dirs = Directory.EnumerateDirectories(current).ToArray();
                files = Directory.EnumerateFiles(current).ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (string file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.EntriesVisited++;
                if (IsDeveloperFile(file)) result.Files.Add(Path.GetFullPath(file));
                if (result.EntriesVisited >= maxEntries) break;
            }
            if (result.EntriesVisited >= maxEntries) break;

            foreach (string dir in dirs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.EntriesVisited++;
                if (result.EntriesVisited >= maxEntries) break;
                var info = new DirectoryInfo(dir);
                if (SkippedDirectories.Contains(info.Name)) continue;
                try { if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                pending.Push(dir);
            }
        }

        result.LimitReached = pending.Count > 0 || result.EntriesVisited >= maxEntries;
        return result;
    }

    private static bool IsDeveloperFile(string path)
    {
        string name = Path.GetFileName(path);
        string ext = Path.GetExtension(path);
        if (DeveloperFileKinds.SolutionExtensions.Contains(ext) || DeveloperFileKinds.ProjectExtensions.Contains(ext) || DeveloperFileKinds.MsBuildExtensions.Contains(ext) || DeveloperFileKinds.SourceExtensions.Contains(ext)) return true;
        return name.Equals("Directory.Build.props", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Build.targets", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Build.rsp", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Solution.props", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Directory.Solution.targets", StringComparison.OrdinalIgnoreCase);
    }
}
