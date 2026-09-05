using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Windows.Persistence;

internal static class StartupPersistenceScanner
{
    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        int files = 0;
        foreach (string root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(root))
                {
                    files++;
                    string ext = Path.GetExtension(file);
                    string command = file;
                    if (ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                        command = TryResolveShortcut(file) ?? file;
                    var finding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.STARTUP_COMMAND", "Suspicious Startup-folder entry", file, command);
                    if (finding is not null) result.Findings.Add(finding);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                if (!ignoreInaccessible) result.Errors.Add(new ScanError("StartupPersistenceScanner", ex.Message, root));
            }
        }
        result.Metrics["startupEntriesInspected"] = files;
    }

    private static string? TryResolveShortcut(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            Type? type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic shortcut = shell.CreateShortcut(path);
            string target = shortcut.TargetPath ?? string.Empty;
            string arguments = shortcut.Arguments ?? string.Empty;
            return (target + " " + arguments).Trim();
        }
        catch { return null; }
    }
}
