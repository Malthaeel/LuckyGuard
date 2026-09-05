using LuckyGuard.Remediation.Execution;

namespace LuckyGuard.Tests;

public sealed class MutationGateTests
{
    [Fact]
    public void Confirmation_IsCaseSensitiveForToken()
    {
        Assert.True(MutationGate.HasConfirmation(["--confirm", "APPLY"], "APPLY"));
        Assert.False(MutationGate.HasConfirmation(["--confirm", "apply"], "APPLY"));
        Assert.False(MutationGate.HasConfirmation(["APPLY"], "APPLY"));
    }
}
