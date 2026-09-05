using System.Net;
using LuckyGuard.Core.Detection;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;
using LuckyGuard.Windows.Network;

namespace LuckyGuard.Tests;

public sealed class NetworkAnalyzerTests
{
    [Fact]
    public void ActiveConfirmedDomainCorrelation_IsCritical()
    {
        var store = new IocStore();
        store.Add(new IocEntry("lw-c2", IocType.Domain, "luckyware.cy", DetectionConfidence.Confirmed, "runtime"));
        var connection = new NetworkConnection(42, IPAddress.Loopback, 50000, IPAddress.Parse("203.0.113.5"), 443, 5, false);
        var finding = Assert.Single(NetworkAnalyzer.Analyze(connection, @"C:\Windows\System32\SndVol.exe", true, ["luckyware.cy"], store, "test"));
        Assert.Equal(DetectionSeverity.Critical, finding.Severity);
        Assert.Equal("LW.NET.CONFIRMED_C2", finding.Id);
    }

    [Fact]
    public void CommunityIpConnection_IsHigh()
    {
        var store = new IocStore();
        store.Add(new IocEntry("ip", IocType.IpAddress, "91.92.243.218", DetectionConfidence.Community, "community"));
        var connection = new NetworkConnection(7, IPAddress.Loopback, 51000, IPAddress.Parse("91.92.243.218"), 443, 5, false);
        var finding = Assert.Single(NetworkAnalyzer.Analyze(connection, @"C:\Temp\a.exe", false, [], store));
        Assert.Equal(DetectionSeverity.High, finding.Severity);
    }

    [Fact]
    public void DnsCacheOnlyConfirmedDomain_IsSuspiciousNotCritical()
    {
        var store = new IocStore();
        store.Add(new IocEntry("lw-c2", IocType.Domain, "luckyware.cy", DetectionConfidence.Confirmed, "runtime"));
        var finding = NetworkAnalyzer.AnalyzeDnsCacheOnly(new DnsCacheEntry("luckyware.cy", 1, "203.0.113.5", 0, 120), store);
        Assert.NotNull(finding);
        Assert.Equal(DetectionSeverity.Suspicious, finding!.Severity);
    }
}
