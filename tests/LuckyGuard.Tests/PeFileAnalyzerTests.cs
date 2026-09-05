using System.Buffers.Binary;
using LuckyGuard.Core.Detection;
using LuckyGuard.PE.Analysis;

namespace LuckyGuard.Tests;

public sealed class PeFileAnalyzerTests
{
    [Fact]
    public void ExecutableRcdEntryPoint_IsCritical()
    {
        string file = MakePe(".rcd1", 0x60000020, 0x1000);
        try
        {
            var findings = new PeFileAnalyzer().Analyze(file, 1024 * 1024);
            Assert.Contains(findings, x => x.Id == "LW.PE.RCD_SECTION" && x.Severity == DetectionSeverity.High);
            Assert.Contains(findings, x => x.Id == "LW.PE.ENTRYPOINT_RCD" && x.Severity == DetectionSeverity.Critical);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void NormalTextSection_DoesNotTriggerLuckyWareRule()
    {
        string file = MakePe(".text", 0x60000020, 0x1000);
        try
        {
            var findings = new PeFileAnalyzer().Analyze(file, 1024 * 1024);
            Assert.DoesNotContain(findings, x => x.Id.StartsWith("LW.PE.", StringComparison.Ordinal));
        }
        finally { File.Delete(file); }
    }


    [Fact]
    public void AnalyzeBytes_UsesVirtualDisplayPath()
    {
        byte[] data = MakePeBytes(".rcd2", 0x60000020, 0x1000);
        var findings = new PeFileAnalyzer().AnalyzeBytes(data, "sample.zip!payload.exe");
        Assert.Contains(findings, x => x.Id == "LW.PE.ENTRYPOINT_RCD" && x.AffectedPath == "sample.zip!payload.exe");
    }

    private static string MakePe(string sectionName, uint characteristics, uint entryPoint)
    {
        byte[] data = MakePeBytes(sectionName, characteristics, entryPoint);
        string path = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N") + ".exe");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, data);
        return path;
    }

    private static byte[] MakePeBytes(string sectionName, uint characteristics, uint entryPoint)
    {
        byte[] data = new byte[0x400];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3C, 4), 0x80);
        data[0x80] = (byte)'P'; data[0x81] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x84, 2), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x86, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94, 2), 0xF0);
        int optional = 0x98;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(optional, 2), 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(optional + 16, 4), entryPoint);
        int section = optional + 0xF0;
        System.Text.Encoding.ASCII.GetBytes(sectionName).CopyTo(data, section);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 36, 4), characteristics);
        return data;
    }
}
