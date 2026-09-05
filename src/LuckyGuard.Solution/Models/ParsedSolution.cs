namespace LuckyGuard.Solution.Models;

public sealed record SolutionProject(string Name, string Path, string? ProjectGuid = null);

public sealed record ParsedSolution(string Path, IReadOnlyList<SolutionProject> Projects);
