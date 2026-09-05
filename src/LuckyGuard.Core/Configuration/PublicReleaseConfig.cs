using System.Text.Json;

namespace LuckyGuard.Core.Configuration;

public sealed class PublicReleaseConfig
{
    public string Repository { get; set; } = "OWNER/REPOSITORY";
    public string PublisherSubject { get; set; } = "PUBLISHER_SUBJECT";
    public string IocFeedUrl { get; set; } = "";
    public string IocSignatureUrl { get; set; } = "";

    public bool IsRepositoryConfigured => Repository != "OWNER/REPOSITORY"
        && System.Text.RegularExpressions.Regex.IsMatch(Repository, @"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$");

    public bool IsPublisherConfigured => !string.IsNullOrWhiteSpace(PublisherSubject)
        && !PublisherSubject.Equals("PUBLISHER_SUBJECT", StringComparison.Ordinal);

    public bool HasOfficialIocEndpoint => Uri.TryCreate(IocFeedUrl, UriKind.Absolute, out var feed)
        && Uri.TryCreate(IocSignatureUrl, UriKind.Absolute, out var sig)
        && feed.Scheme == Uri.UriSchemeHttps
        && sig.Scheme == Uri.UriSchemeHttps
        && string.Equals(feed.Host, sig.Host, StringComparison.OrdinalIgnoreCase);

    public static PublicReleaseConfig? LoadDefault()
    {
        foreach (string path in CandidatePaths())
        {
            if (!File.Exists(path)) continue;
            try
            {
                return JsonSerializer.Deserialize<PublicReleaseConfig>(File.ReadAllText(path), new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            }
            catch { return null; }
        }
        return null;
    }

    public static IEnumerable<string> CandidatePaths()
    {
        yield return Path.Combine(AppContext.BaseDirectory, "config", "public-release.json");
        yield return Path.Combine(Environment.CurrentDirectory, "config", "public-release.json");
    }
}
