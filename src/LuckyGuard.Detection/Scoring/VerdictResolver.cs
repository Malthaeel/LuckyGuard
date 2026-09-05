using LuckyGuard.Core;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Detection.Scoring;

public static class VerdictResolver
{
    public static Verdict Resolve(ScanResult result)
    {
        if (result.Errors.Count > 0) return result.Findings.Count == 0 ? Verdict.Incomplete : MaxFindingVerdict(result.Findings);
        if (result.Findings.Count == 0) return result.Verdict == Verdict.NotAssessed ? Verdict.NotAssessed : Verdict.Clean;
        return MaxFindingVerdict(result.Findings);
    }

    private static Verdict MaxFindingVerdict(IEnumerable<DetectionFinding> findings)
    {
        var max = findings.Max(f => f.Severity);
        return max switch
        {
            DetectionSeverity.Critical => Verdict.Critical,
            DetectionSeverity.High => Verdict.High,
            DetectionSeverity.Suspicious => Verdict.Suspicious,
            DetectionSeverity.Low or DetectionSeverity.Informational => Verdict.Informational,
            _ => Verdict.NotAssessed
        };
    }

    public static int ToExitCode(Verdict verdict) => verdict switch
    {
        Verdict.Clean => ExitCodes.Success,
        Verdict.Informational => ExitCodes.Informational,
        Verdict.Suspicious => ExitCodes.Suspicious,
        Verdict.High => ExitCodes.High,
        Verdict.Critical => ExitCodes.Critical,
        Verdict.NotAssessed or Verdict.Incomplete => ExitCodes.Incomplete,
        Verdict.Failed => ExitCodes.Failure,
        _ => ExitCodes.Failure
    };
}
