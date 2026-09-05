using LuckyGuard.Core;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Reporting;

public static class TextReportWriter
{
    public static string Write(ScanResult result)
    {
        var lines = new List<string>
        {
            $"LuckyGuard {BuildInfo.Version}",
            new string('─', 58),
            $"Target : {result.Target.Kind} {result.Target.Value}",
            $"Verdict: {result.Verdict.ToString().ToUpperInvariant()}",
            $"Findings: {result.Findings.Count}",
            $"Errors  : {result.Errors.Count}"
        };

        if (result.Metrics.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Metrics");
            foreach (var item in result.Metrics.OrderBy(k => k.Key)) lines.Add($"  {item.Key}: {item.Value}");
        }

        if (result.Findings.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Findings");
            foreach (var finding in result.Findings)
            {
                lines.Add($"  [{finding.Severity}] {finding.Id} - {finding.Title}");
                if (!string.IsNullOrWhiteSpace(finding.AffectedPath)) lines.Add($"    Path: {finding.AffectedPath}");
                lines.Add($"    Confidence: {finding.Confidence}");
                lines.Add($"    {finding.Description}");
                if (finding.Evidence is { Count: > 0 })
                    foreach (var evidence in finding.Evidence) lines.Add($"    Evidence: {evidence.Kind}={evidence.Value}{(string.IsNullOrWhiteSpace(evidence.Source) ? string.Empty : $" ({evidence.Source})")}");
            }
        }

        if (result.Errors.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Errors");
            foreach (var error in result.Errors) lines.Add($"  [{error.Scanner}] {error.Message} {error.Path}".TrimEnd());
        }

        if (result.Notes.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Notes");
            foreach (var note in result.Notes) lines.Add($"  - {note}");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
