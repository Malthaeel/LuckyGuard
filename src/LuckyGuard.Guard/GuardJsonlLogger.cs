using System.Text.Json;

namespace LuckyGuard.Guard;

public sealed class GuardJsonlLogger
{
    private readonly object _sync = new();
    public string Path { get; }

    public GuardJsonlLogger(string? path = null)
    {
        Path = path ?? GetDefaultPath();
    }

    public void Write(GuardAlert alert)
    {
        try
        {
            string? dir = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
            var entry = new
            {
                timestampUtc = alert.ObservedAtUtc,
                source = alert.Source.ToString(),
                alert.Subject,
                alert.Message,
                verdict = alert.Result?.Verdict.ToString(),
                findings = alert.Result?.Findings.Select(f => new
                {
                    f.Id, f.Title, severity = f.Severity.ToString(), confidence = f.Confidence.ToString(), f.AffectedPath,
                    evidence = f.Evidence?.Select(e => new { e.Kind, e.Value })
                })
            };
            string line = JsonSerializer.Serialize(entry);
            lock (_sync) File.AppendAllText(Path, line + Environment.NewLine);
        }
        catch { }
    }

    public static string GetDefaultPath() => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LuckyGuard", "Guard", "guard.jsonl");
}
