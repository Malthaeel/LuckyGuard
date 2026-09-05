using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Analysis;
using System.Text.RegularExpressions;

namespace LuckyGuard.Windows.Persistence;

internal static class PersistenceFindingFactory
{
    public static DetectionFinding? FromCommand(string id, string title, string location, string? command, bool persistenceContext = true, IEnumerable<Evidence>? extraEvidence = null)
    {
        var assessment = CommandRiskAnalyzer.Analyze(command, persistenceContext);
        if (assessment is null) return null;
        IEnumerable<Evidence> allEvidence = assessment.Evidence;
        if (extraEvidence is not null) allEvidence = allEvidence.Concat(extraEvidence);
        allEvidence = allEvidence.Concat([new Evidence("command", Truncate(RedactSecrets(command ?? string.Empty)))]);
        return new DetectionFinding(id, title, DetectionCategory.Persistence, assessment.Severity, assessment.Confidence,
            assessment.Reason, location, allEvidence.ToArray());
    }

    public static string Truncate(string text, int max = 512) => text.Length <= max ? text : text[..max] + "…";

    private static string RedactSecrets(string text) => Regex.Replace(text, @"(?i)(password|passwd|token|secret|api[_-]?key)(\s*[=:]\s*|\s+)([^\s""]+|""[^""]*"")", "$1$2<redacted>", RegexOptions.CultureInvariant);
}
