using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardServiceManagerPolicyTests
{
    [Fact]
    public void CreateArguments_UseOwnProcessExecutableAndAutomaticStart()
    {
        string fake = Path.Combine(Path.GetTempPath(), "LuckyGuardService.exe");
        IReadOnlyList<string> args = GuardServiceManager.BuildCreateArguments(fake);
        Assert.Equal("create", args[0]);
        Assert.Contains(GuardServiceManager.ServiceName, args);
        Assert.Contains("start=", args);
        Assert.Contains("auto", args);
        Assert.Contains(args, a => a.Contains("--service", StringComparison.Ordinal));
    }

    [Fact]
    public void ServiceIdentity_IsStable()
    {
        Assert.Equal("LuckyGuardGuard", GuardServiceManager.ServiceName);
        Assert.Equal("LuckyGuard Realtime Guard", GuardServiceManager.DisplayName);
    }
}
