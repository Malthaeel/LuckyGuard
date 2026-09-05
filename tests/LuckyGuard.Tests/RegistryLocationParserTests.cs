using LuckyGuard.Remediation.Planning;

namespace LuckyGuard.Tests;

public sealed class RegistryLocationParserTests
{
    [Theory]
    [InlineData("CurrentUser\\Software\\X::Value", "HKCU", "Software\\X", "Value")]
    [InlineData("LocalMachine\\Software\\X::Value", "HKLM", "Software\\X", "Value")]
    [InlineData("HKLM\\Software\\X::Debugger", "HKLM", "Software\\X", "Debugger")]
    public void ParsesSupportedLocations(string input, string hive, string subKey, string value)
    {
        Assert.True(RegistryLocationParser.TryParseValueLocation(input, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(hive, parsed!.Hive);
        Assert.Equal(subKey, parsed.SubKey);
        Assert.Equal(value, parsed.ValueName);
    }
}
