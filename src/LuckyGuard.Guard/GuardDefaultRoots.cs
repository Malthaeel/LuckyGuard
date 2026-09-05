namespace LuckyGuard.Guard;

public static class GuardDefaultRoots
{
    public static IReadOnlyList<string> GetDefaultRoots()
    {
        var roots = new List<string>();
        Add(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        Add(roots, Path.GetTempPath());
        Add(roots, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        Add(roots, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        Add(roots, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        Add(roots, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        return GuardOptions.NormalizeRoots(roots);
    }

    private static void Add(List<string> roots, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path)) roots.Add(path);
    }
}
