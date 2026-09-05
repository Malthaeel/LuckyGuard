using LuckyGuard.Ioc.Feed;

namespace LuckyGuard.Tests;

public sealed class IocPublicKeyPinTests
{
    [Fact]
    public void ShippedPublicKey_MatchesEmbeddedPin()
    {
        string root = FindRepoRoot();
        string pem = File.ReadAllText(Path.Combine(root, "rules", "luckyware", "ioc-public-key.pem"));
        Assert.True(IocPublicKeyPin.IsExpected(pem));
    }

    [Fact]
    public void AlteredPublicKey_IsRejected()
    {
        Assert.False(IocPublicKeyPin.IsExpected("-----BEGIN PUBLIC KEY-----\\nAAAA\\n-----END PUBLIC KEY-----"));
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
