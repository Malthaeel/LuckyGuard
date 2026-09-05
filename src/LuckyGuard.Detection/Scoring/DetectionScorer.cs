using LuckyGuard.Core.Detection;

namespace LuckyGuard.Detection.Scoring;

public static class DetectionScorer
{
    public static int Score(DetectionFinding finding)
    {
        int severity = finding.Severity switch
        {
            DetectionSeverity.Informational => 1,
            DetectionSeverity.Low => 10,
            DetectionSeverity.Suspicious => 35,
            DetectionSeverity.High => 70,
            DetectionSeverity.Critical => 100,
            _ => 0
        };

        int confidenceBonus = finding.Confidence switch
        {
            DetectionConfidence.Heuristic => 0,
            DetectionConfidence.Community => 5,
            DetectionConfidence.Reversed => 10,
            DetectionConfidence.Confirmed => 20,
            _ => 0
        };

        return severity + confidenceBonus;
    }
}
