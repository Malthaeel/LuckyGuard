using LuckyGuard.Core.Configuration;

namespace LuckyGuard.Tests;

public sealed class ReleaseVersionPolicyTests
{
    [Theory]
    [InlineData("1.0.0-rc.1", "v1.0.0", true)]
    [InlineData("1.0.0-rc.1", "v0.9.9", false)]
    [InlineData("1.0.0", "v1.0.1", true)]
    [InlineData("1.0.0", "v1.0.0", false)]
    [InlineData("1.0.0", "v1.1.0-rc.1", false)]
    public void StableReleaseComparison_IsConservative(string current, string latest, bool expected)
    {
        Assert.Equal(expected, ReleaseVersionPolicy.IsNewerStableRelease(current, latest));
    }
}
