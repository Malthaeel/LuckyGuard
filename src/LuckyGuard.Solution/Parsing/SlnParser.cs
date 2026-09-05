using System.Text.RegularExpressions;
using LuckyGuard.Solution.Models;

namespace LuckyGuard.Solution.Parsing;

public static partial class SlnParser
{
    [GeneratedRegex("^Project\\(\\\"[^\\\"]+\\\"\\)\\s*=\\s*\\\"(?<name>[^\\\"]+)\\\",\\s*\\\"(?<path>[^\\\"]+)\\\",\\s*\\\"(?<guid>[^\\\"]+)\\\"", RegexOptions.IgnoreCase)]
    private static partial Regex ProjectLineRegex();

    public static ParsedSolution Parse(string solutionPath)
    {
        string full = Path.GetFullPath(solutionPath);
        string baseDir = Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory();
        var projects = new List<SolutionProject>();

        foreach (string line in File.ReadLines(full))
        {
            var match = ProjectLineRegex().Match(line);
            if (!match.Success) continue;

            string relative = match.Groups["path"].Value.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar);
            string extension = Path.GetExtension(relative);
            if (!DeveloperFileKinds.ProjectExtensions.Contains(extension)) continue;

            string resolved = Path.GetFullPath(Path.Combine(baseDir, relative));
            projects.Add(new SolutionProject(match.Groups["name"].Value, resolved, match.Groups["guid"].Value));
        }

        return new ParsedSolution(full, projects);
    }
}
