using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Windows.Network;

internal static class NetworkScanCompletion
{
    internal static void MarkAssessed(ScanResult result)
    {
        if (result.Findings.Count == 0 && result.Errors.Count == 0)
            result.Verdict = Verdict.Clean;
    }
}
