using LuckyGuard.Defender;

namespace LuckyGuard.Tests;

public sealed class DefenderBridgeTests
{
    [Fact]
    public void StatusJson_ParsesProtectionFlags()
    {
        const string json = "{\"AntivirusEnabled\":true,\"RealTimeProtectionEnabled\":true,\"BehaviorMonitorEnabled\":true,\"IoavProtectionEnabled\":true,\"AntispywareEnabled\":true,\"AntivirusSignatureVersion\":\"1.2.3.4\",\"AntivirusSignatureLastUpdated\":\"2026-09-04T12:00:00+03:00\"}";
        DefenderStatus status = DefenderBridge.ParseStatusJson(json);
        Assert.True(status.Available);
        Assert.True(status.AntivirusEnabled);
        Assert.True(status.RealTimeProtectionEnabled);
        Assert.Equal("1.2.3.4", status.AntivirusSignatureVersion);
        Assert.NotNull(status.AntivirusSignatureLastUpdated);
    }

    [Fact]
    public void StatusJson_MissingFlags_DefaultsFalse()
    {
        DefenderStatus status = DefenderBridge.ParseStatusJson("{}");
        Assert.True(status.Available);
        Assert.False(status.AntivirusEnabled);
        Assert.False(status.RealTimeProtectionEnabled);
    }
}
