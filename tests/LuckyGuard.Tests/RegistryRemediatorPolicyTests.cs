using LuckyGuard.Remediation.Execution;

namespace LuckyGuard.Tests;

public sealed class RegistryRemediatorPolicyTests
{
    [Theory]
    [InlineData("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Anything", true)]
    [InlineData("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Anything", true)]
    [InlineData("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe", "Debugger", true)]
    [InlineData("HKCU", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe", "Debugger", false)]
    [InlineData("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe", "GlobalFlag", false)]
    [InlineData("HKLM", "SYSTEM\\CurrentControlSet\\Services\\x", "ImagePath", false)]
    public void AllowedLocationPolicy_IsNarrow(string hive, string key, string value, bool expected)
        => Assert.Equal(expected, RegistryRemediator.IsAllowedRemediationLocation(hive, key, value));
}
