using LuckyGuard.Core.Detection;
using LuckyGuard.Suo;

namespace LuckyGuard.Tests;

public sealed class SuoFileAnalyzerTests
{
    [Fact]
    public void CompoundFileWithKnownMarker_IsDetected()
    {
        string file = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N") + ".suo");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        byte[] data = new byte[512];
        byte[] magic = [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1];
        magic.CopyTo(data, 0);
        System.Text.Encoding.ASCII.GetBytes("NtExploreProcess VCCHelp").CopyTo(data, 64);
        File.WriteAllBytes(file, data);
        try
        {
            var finding = Assert.Single(new SuoFileAnalyzer().Analyze(file, 1024 * 1024), x => x.Id == "LW.SUO.KNOWN_MARKER");
            Assert.Equal(DetectionSeverity.High, finding.Severity);
        }
        finally { File.Delete(file); }
    }
}
