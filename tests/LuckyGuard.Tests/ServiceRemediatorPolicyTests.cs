using LuckyGuard.Remediation.Execution;

namespace LuckyGuard.Tests;

public sealed class ServiceRemediatorPolicyTests
{
    [Theory]
    [InlineData("BadSvc")]
    [InlineData("cpuz154")]
    [InlineData("Vendor.Service-1")]
    public void NormalServiceNames_AreAccepted(string name) => ServiceRemediator.ValidateServiceName(name);

    [Theory]
    [InlineData("")]
    [InlineData("bad service")]
    [InlineData("bad&whoami")]
    [InlineData("../svc")]
    public void UnsafeServiceNames_AreRejected(string name) => Assert.Throws<ArgumentException>(() => ServiceRemediator.ValidateServiceName(name));
}
