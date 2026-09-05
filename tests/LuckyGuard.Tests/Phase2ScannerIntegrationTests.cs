using System.Buffers.Binary;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.PE;
using LuckyGuard.Suo;

namespace LuckyGuard.Tests;

public sealed class Phase2ScannerIntegrationTests
{
    [Fact]
    public async Task FileTarget_WithRcdPe_IsCriticalAfterVerdictResolutionInput()
    {
        string file = CreateRcdPe();
        try
        {
            var result = await new ScanCoordinator([new BaselineTargetScanner(), new PeScanner(), new SuoScanner()])
                .ScanAsync(new ScanTarget(ScanTargetKind.File, file));
            Assert.Contains(result.Findings, x => x.Id == "LW.PE.ENTRYPOINT_RCD");
            Assert.Equal(1, result.Metrics["peFilesAnalyzed"]);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task CleanNonPeFile_RemainsNotAssessed()
    {
        string file = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N") + ".txt");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "hello");
        try
        {
            var result = await new ScanCoordinator([new BaselineTargetScanner(), new PeScanner(), new SuoScanner()])
                .ScanAsync(new ScanTarget(ScanTargetKind.File, file));
            Assert.Empty(result.Findings);
            Assert.Equal(Verdict.NotAssessed, result.Verdict);
        }
        finally { File.Delete(file); }
    }

    private static string CreateRcdPe()
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
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(optional + 16, 4), 0x1000);
        int section = optional + 0xF0;
        System.Text.Encoding.ASCII.GetBytes(".rcdT").CopyTo(data, section);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 36, 4), 0x60000020);
        string path = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N") + ".exe");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, data);
        return path;
    }
}
