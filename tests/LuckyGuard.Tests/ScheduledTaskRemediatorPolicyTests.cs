using LuckyGuard.Remediation.Execution;

namespace LuckyGuard.Tests;

public sealed class ScheduledTaskRemediatorPolicyTests
{
    [Fact]
    public void PasswordLogon_IsNotAutoRestorable()
    {
        const string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal><LogonType>Password</LogonType></Principal></Principals></Task>";
        Assert.False(ScheduledTaskRemediator.CanRestoreWithoutSecret(xml));
    }

    [Fact]
    public void ServiceAccountLogon_IsAutoRestorableWithoutSecret()
    {
        const string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal><LogonType>ServiceAccount</LogonType></Principal></Principals></Task>";
        Assert.True(ScheduledTaskRemediator.CanRestoreWithoutSecret(xml));
    }

    [Fact]
    public void MalformedXml_IsNotAutoRestorable()
    {
        Assert.False(ScheduledTaskRemediator.CanRestoreWithoutSecret("<Task>"));
    }
}
