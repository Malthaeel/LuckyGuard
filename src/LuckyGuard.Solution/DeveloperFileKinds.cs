namespace LuckyGuard.Solution;

public static class DeveloperFileKinds
{
    public static readonly HashSet<string> SolutionExtensions = new(StringComparer.OrdinalIgnoreCase) { ".sln", ".slnx" };
    public static readonly HashSet<string> ProjectExtensions = new(StringComparer.OrdinalIgnoreCase) { ".vcxproj", ".csproj", ".fsproj", ".vbproj" };
    public static readonly HashSet<string> MsBuildExtensions = new(StringComparer.OrdinalIgnoreCase) { ".vcxproj", ".csproj", ".fsproj", ".vbproj", ".props", ".targets", ".user" };
    public static readonly HashSet<string> SourceExtensions = new(StringComparer.OrdinalIgnoreCase) { ".cpp", ".cc", ".c", ".h", ".hpp" };
}
