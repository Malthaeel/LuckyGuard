namespace LuckyGuard.Guard;

public static class GuardInternalPaths
{
    public static string ProgramDataRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LuckyGuard");
    public static string LocalDataRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LuckyGuard");

    public static bool IsInternalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            string full = Path.GetFullPath(path);
            return IsSameOrChild(full, ProgramDataRoot) || IsSameOrChild(full, LocalDataRoot);
        }
        catch { return false; }
    }

    private static bool IsSameOrChild(string candidate, string parent)
    {
        if (string.IsNullOrWhiteSpace(parent)) return false;
        string normalizedParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        string normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        if (normalizedCandidate.Equals(normalizedParent, StringComparison.OrdinalIgnoreCase)) return true;
        return normalizedCandidate.StartsWith(normalizedParent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
