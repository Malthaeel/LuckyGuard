using LuckyGuard.Core.Detection;

namespace LuckyGuard.MSBuild.Analysis;

public sealed class MsBuildAnalysisResult
{
    public List<DetectionFinding> Findings { get; } = [];
    public HashSet<string> FilesAnalyzed { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int ImportsFollowed { get; set; }
    public List<(string Path, string Message)> Errors { get; } = [];
}
