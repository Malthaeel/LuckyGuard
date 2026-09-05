namespace LuckyGuard.SDK.Discovery;

public static class SdkPathDiscovery
{
    public static IReadOnlyList<string> Discover()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddWindowsKits(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), roots);
        AddVisualStudio(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), roots);
        AddVisualStudio(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), roots);
        return roots.Where(Directory.Exists).Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddWindowsKits(string basePath, HashSet<string> roots)
    {
        if (string.IsNullOrWhiteSpace(basePath)) return;
        string include = Path.Combine(basePath, "Windows Kits", "10", "Include");
        if (Directory.Exists(include)) roots.Add(include);
    }

    private static void AddVisualStudio(string basePath, HashSet<string> roots)
    {
        if (string.IsNullOrWhiteSpace(basePath)) return;
        string vs = Path.Combine(basePath, "Microsoft Visual Studio");
        if (!Directory.Exists(vs)) return;
        try
        {
            foreach (string include in Directory.EnumerateDirectories(vs, "include", SearchOption.AllDirectories))
            {
                string normalized = include.Replace('/', '\\');
                if (normalized.Contains("\\VC\\Tools\\MSVC\\", StringComparison.OrdinalIgnoreCase)) roots.Add(include);
            }
        }
        catch { }
    }
}
