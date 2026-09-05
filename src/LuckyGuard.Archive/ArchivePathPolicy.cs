namespace LuckyGuard.Archive;

public static class ArchivePathPolicy
{
    public static bool IsTraversalLike(string fullName)
    {
        if (string.IsNullOrWhiteSpace(fullName)) return false;
        string normalized = fullName.Replace('\\', '/');
        if (normalized.StartsWith("/", StringComparison.Ordinal) || normalized.StartsWith("//", StringComparison.Ordinal)) return true;
        if (normalized.Length >= 2 && char.IsLetter(normalized[0]) && normalized[1] == ':') return true;
        return normalized.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(part => part == "..");
    }
}
