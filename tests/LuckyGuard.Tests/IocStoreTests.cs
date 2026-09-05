using LuckyGuard.Core.Detection;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Tests;

public sealed class IocStoreTests
{
    [Fact]
    public void DomainMatch_IncludesSubdomains()
    {
        var store = new IocStore();
        store.Add(new IocEntry("c2", IocType.Domain, "luckyware.cy", DetectionConfidence.Confirmed, "test"));
        Assert.True(store.TryMatchDomain("api.luckyware.cy", out var match));
        Assert.Equal("c2", match!.Id);
    }

    [Fact]
    public void IpAddress_NormalizesEquivalentText()
    {
        var store = new IocStore();
        store.Add(new IocEntry("ip", IocType.IpAddress, "2001:0db8::1", DetectionConfidence.Community, "test"));
        Assert.True(store.TryMatch(IocType.IpAddress, "2001:db8:0:0:0:0:0:1", out _));
    }
}
