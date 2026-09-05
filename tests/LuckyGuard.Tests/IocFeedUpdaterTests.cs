using System.Net;
using LuckyGuard.Ioc.Feed;

namespace LuckyGuard.Tests;

public sealed class IocFeedUpdaterTests
{
    [Fact]
    public async Task ValidSignedFeed_IsInstalled()
    {
        using var temp = new TestTempDirectory();
        string root = FindRepoRoot();
        byte[] feed = File.ReadAllBytes(Path.Combine(root, "rules", "luckyware", "ioc-feed.json"));
        byte[] sig = File.ReadAllBytes(Path.Combine(root, "rules", "luckyware", "ioc-feed.sig"));
        string pub = Path.Combine(root, "rules", "luckyware", "ioc-public-key.pem");
        string destFeed = Path.Combine(temp.Path, "ioc-feed.json");
        string destSig = Path.Combine(temp.Path, "ioc-feed.sig");
        File.WriteAllBytes(destFeed, feed); File.WriteAllBytes(destSig, sig);
        using var client = new HttpClient(new FakeHandler(feed, sig));
        var result = await new IocFeedUpdater().UpdateAsync(
            new Uri("https://updates.example/feed"), new Uri("https://updates.example/sig"), destFeed, destSig, pub, client);
        Assert.True(result.Entries > 0);
        Assert.Equal(feed, File.ReadAllBytes(destFeed));
    }

    [Fact]
    public async Task InvalidSignature_DoesNotReplaceExistingFeed()
    {
        using var temp = new TestTempDirectory();
        string root = FindRepoRoot();
        byte[] originalFeed = File.ReadAllBytes(Path.Combine(root, "rules", "luckyware", "ioc-feed.json"));
        byte[] originalSig = File.ReadAllBytes(Path.Combine(root, "rules", "luckyware", "ioc-feed.sig"));
        string pub = Path.Combine(root, "rules", "luckyware", "ioc-public-key.pem");
        string destFeed = Path.Combine(temp.Path, "ioc-feed.json");
        string destSig = Path.Combine(temp.Path, "ioc-feed.sig");
        File.WriteAllBytes(destFeed, originalFeed); File.WriteAllBytes(destSig, originalSig);
        using var client = new HttpClient(new FakeHandler(originalFeed, System.Text.Encoding.UTF8.GetBytes("not-a-valid-signature")));
        await Assert.ThrowsAsync<InvalidDataException>(() => new IocFeedUpdater().UpdateAsync(
            new Uri("https://updates.example/feed"), new Uri("https://updates.example/sig"), destFeed, destSig, pub, client));
        Assert.Equal(originalFeed, File.ReadAllBytes(destFeed));
        Assert.Equal(originalSig, File.ReadAllBytes(destSig));
    }

    [Fact]
    public void SystemUpdatePaths_UseCommonApplicationDataLuckyGuardRules()
    {
        var paths = IocFeedLoader.GetSystemUpdatePaths();
        string expectedTail = Path.Combine("LuckyGuard", "Rules", "luckyware", "ioc-feed.json");
        string expectedSigTail = Path.Combine("LuckyGuard", "Rules", "luckyware", "ioc-feed.sig");
        Assert.EndsWith(expectedTail, paths.Feed, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(expectedSigTail, paths.Signature, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HttpUrl_IsRejectedBeforeNetworkAccess()
    {
        using var temp = new TestTempDirectory();
        string root = FindRepoRoot();
        string pub = Path.Combine(root, "rules", "luckyware", "ioc-public-key.pem");
        await Assert.ThrowsAsync<ArgumentException>(() => new IocFeedUpdater().UpdateAsync(
            new Uri("http://updates.example/feed"), new Uri("https://updates.example/sig"), Path.Combine(temp.Path,"f"), Path.Combine(temp.Path,"s"), pub));
    }

    private sealed class FakeHandler(byte[] feed, byte[] sig) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[] body = request.RequestUri!.AbsolutePath.EndsWith("sig", StringComparison.OrdinalIgnoreCase) ? sig : feed;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? d = new(AppContext.BaseDirectory);
        while (d is not null)
        {
            if (File.Exists(Path.Combine(d.FullName, "LuckyGuard.sln"))) return d.FullName;
            d = d.Parent;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }
}
