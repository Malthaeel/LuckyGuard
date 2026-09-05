namespace LuckyGuard.MSBuild.Discovery;

public static class ParentBuildFileDiscovery
{
    private static readonly string[] FixedNames =
    [
        "Directory.Build.props", "Directory.Build.targets", "Directory.Build.rsp",
        "Directory.Solution.props", "Directory.Solution.targets"
    ];

    public static IReadOnlyList<string> Discover(string startDirectory)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DirectoryInfo? dir = new(Path.GetFullPath(startDirectory));
        while (dir is not null)
        {
            foreach (string name in FixedNames)
            {
                string candidate = Path.Combine(dir.FullName, name);
                if (File.Exists(candidate)) found.Add(candidate);
            }

            foreach (string pattern in new[] { "before.*.sln.targets", "after.*.sln.targets", "before.*.slnx.targets", "after.*.slnx.targets" })
            {
                try { foreach (string candidate in Directory.EnumerateFiles(dir.FullName, pattern, SearchOption.TopDirectoryOnly)) found.Add(candidate); }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            dir = dir.Parent;
        }
        return found.ToArray();
    }
}
