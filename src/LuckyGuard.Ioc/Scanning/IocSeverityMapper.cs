using LuckyGuard.Core.Detection;

namespace LuckyGuard.Ioc.Scanning;

public static class IocSeverityMapper
{
    public static DetectionSeverity ForDirectMatch(DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.Confirmed => DetectionSeverity.Critical,
        DetectionConfidence.Reversed => DetectionSeverity.High,
        DetectionConfidence.Community => DetectionSeverity.High,
        _ => DetectionSeverity.Suspicious
    };

    public static DetectionSeverity ForFilenameMatch(DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.Confirmed => DetectionSeverity.High,
        DetectionConfidence.Reversed => DetectionSeverity.Suspicious,
        DetectionConfidence.Community => DetectionSeverity.Suspicious,
        _ => DetectionSeverity.Low
    };

    public static DetectionSeverity ForCacheOnly(DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.Confirmed => DetectionSeverity.Suspicious,
        DetectionConfidence.Reversed => DetectionSeverity.Low,
        DetectionConfidence.Community => DetectionSeverity.Low,
        _ => DetectionSeverity.Informational
    };
}
