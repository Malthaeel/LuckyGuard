using LuckyGuard.Core.Configuration;

namespace LuckyGuard.Tests;

public sealed class PublicReleaseConfigTests
{
    [Fact]
    public void PlaceholderConfig_IsNotPublicConfigured()
    {
        var c = new PublicReleaseConfig
        {
            Repository = "OWNER/REPOSITORY",
            PublisherSubject = "PUBLISHER_SUBJECT",
            IocFeedUrl = "https://raw.githubusercontent.com/OWNER/REPOSITORY/main/rules/luckyware/ioc-feed.json",
            IocSignatureUrl = "https://raw.githubusercontent.com/OWNER/REPOSITORY/main/rules/luckyware/ioc-feed.sig"
        };
        Assert.False(c.IsRepositoryConfigured);
        Assert.False(c.IsPublisherConfigured);
    }


    [Fact]
    public void RepositoryCanBeConfiguredBeforePublisherIdentityExists()
    {
        var c = new PublicReleaseConfig
        {
            Repository = "owner/LuckyGuard",
            PublisherSubject = "PUBLISHER_SUBJECT",
            IocFeedUrl = "https://raw.githubusercontent.com/owner/LuckyGuard/main/rules/luckyware/ioc-feed.json",
            IocSignatureUrl = "https://raw.githubusercontent.com/owner/LuckyGuard/main/rules/luckyware/ioc-feed.sig"
        };
        Assert.True(c.IsRepositoryConfigured);
        Assert.False(c.IsPublisherConfigured);
        Assert.True(c.HasOfficialIocEndpoint);
    }

    [Fact]
    public void ConfiguredSameHostHttpsIocEndpoints_AreAccepted()
    {
        var c = new PublicReleaseConfig
        {
            Repository = "owner/LuckyGuard",
            PublisherSubject = "CN=LuckyGuard Project",
            IocFeedUrl = "https://raw.githubusercontent.com/owner/LuckyGuard/main/rules/luckyware/ioc-feed.json",
            IocSignatureUrl = "https://raw.githubusercontent.com/owner/LuckyGuard/main/rules/luckyware/ioc-feed.sig"
        };
        Assert.True(c.IsRepositoryConfigured);
        Assert.True(c.IsPublisherConfigured);
        Assert.True(c.HasOfficialIocEndpoint);
    }

    [Theory]
    [InlineData("owner/")]
    [InlineData("/repo")]
    [InlineData("owner/repo/extra")]
    [InlineData("owner repo/LuckyGuard")]
    public void MalformedRepository_IsRejected(string repository)
    {
        Assert.False(new PublicReleaseConfig { Repository = repository }.IsRepositoryConfigured);
    }

    [Fact]
    public void MixedHostIocEndpoints_AreRejected()
    {
        var c = new PublicReleaseConfig
        {
            Repository = "owner/LuckyGuard",
            IocFeedUrl = "https://raw.githubusercontent.com/owner/LuckyGuard/main/rules/luckyware/ioc-feed.json",
            IocSignatureUrl = "https://example.com/ioc-feed.sig"
        };
        Assert.False(c.HasOfficialIocEndpoint);
    }
}
