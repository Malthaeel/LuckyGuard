using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using LuckyGuard.Archive;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Tests;

public sealed class ArchiveScannerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));

    public ArchiveScannerTests() => Directory.CreateDirectory(_root);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    [Fact]
    public async Task SourceMarkersInsideZip_AreDetected()
    {
        string zip = CreateZip(("src/test.cpp", "// VccLibaries NtExploreProcess"));
        ScanResult result = await Scan(zip, new ArchiveScanner());
        DetectionFinding finding = Assert.Single(result.Findings, f => f.Id == "LW.SOURCE.KNOWN_MARKER");
        Assert.Equal(DetectionSeverity.High, finding.Severity);
        Assert.Contains("!src/test.cpp", finding.AffectedPath!);
    }

    [Fact]
    public async Task TraversalEntry_IsDetectedWithoutExtraction()
    {
        string zip = CreateZip(("../evil.txt", "hello"));
        ScanResult result = await Scan(zip, new ArchiveScanner());
        Assert.Contains(result.Findings, f => f.Id == "LG.ARCHIVE.PATH_TRAVERSAL");
        Assert.False(File.Exists(Path.Combine(_root, "evil.txt")));
    }

    [Fact]
    public async Task EntryCountLimit_StopsDeepScan()
    {
        string zip = CreateZip(("a.txt", "a"), ("b.txt", "b"));
        var limits = new ArchiveScanLimits { MaxEntries = 1 };
        ScanResult result = await Scan(zip, new ArchiveScanner(limits: limits));
        Assert.Contains(result.Findings, f => f.Id == "LG.ARCHIVE.ENTRY_LIMIT");
    }

    [Fact]
    public async Task EntrySizeLimit_IsReported()
    {
        string zip = CreateZip(("big.bin", new string('A', 128)));
        var limits = new ArchiveScanLimits { MaxEntryScanBytes = 64 };
        ScanResult result = await Scan(zip, new ArchiveScanner(limits: limits));
        Assert.Contains(result.Findings, f => f.Id == "LG.ARCHIVE.ENTRY_SIZE_LIMIT");
    }

    [Fact]
    public async Task TotalDeclaredLimit_IsReported()
    {
        string zip = CreateZip(("a.bin", new string('A', 80)), ("b.bin", new string('B', 80)));
        var limits = new ArchiveScanLimits { MaxDeclaredUncompressedBytes = 100, MaxEntryScanBytes = 1000 };
        ScanResult result = await Scan(zip, new ArchiveScanner(limits: limits));
        Assert.Contains(result.Findings, f => f.Id == "LG.ARCHIVE.TOTAL_SIZE_LIMIT");
    }


    [Fact]
    public async Task LuckyWareRcdPeInsideZip_IsDetectedWithoutExtraction()
    {
        byte[] pe = BuildPeBytes(".rcd1", 0x60000020, 0x1000);
        string zip = CreateZipBytes(("bin/payload.exe", pe));
        ScanResult result = await Scan(zip, new ArchiveScanner());
        Assert.Contains(result.Findings, f => f.Id == "LW.PE.RCD_SECTION");
        Assert.Contains(result.Findings, f => f.Id == "LW.PE.ENTRYPOINT_RCD" && f.AffectedPath!.Contains("!bin/payload.exe", StringComparison.Ordinal));
    }

    [Fact]
    public async Task FilenameIocInsideZip_IsDetected()
    {
        var store = new IocStore();
        store.Add(new IocEntry("file-test", IocType.FileName, "Retev.exe", DetectionConfidence.Community, "test"));
        string zip = CreateZip(("bin/Retev.exe", "not a PE"));
        ScanResult result = await Scan(zip, new ArchiveScanner(store, "test-feed"));
        Assert.Contains(result.Findings, f => f.Id == "LW.ARCHIVE.IOC_FILENAME");
    }

    [Fact]
    public async Task Sha256IocInsideZip_IsDetected()
    {
        byte[] payload = "known payload"u8.ToArray();
        string hash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var store = new IocStore();
        store.Add(new IocEntry("hash-test", IocType.Sha256, hash, DetectionConfidence.Confirmed, "test"));
        string zip = CreateZipBytes(("bin/test.exe", payload));
        ScanResult result = await Scan(zip, new ArchiveScanner(store, "test-feed"));
        DetectionFinding finding = Assert.Single(result.Findings, f => f.Id == "LW.ARCHIVE.IOC_SHA256");
        Assert.Equal(DetectionSeverity.Critical, finding.Severity);
    }

    [Fact]
    public async Task NestedZip_IsInspectedWithinDepthBudget()
    {
        byte[] inner = BuildZipBytes(("inner.cpp", "// VccLibaries NtExploreProcess"));
        string outer = CreateZipBytes(("nested.zip", inner));
        ScanResult result = await Scan(outer, new ArchiveScanner());
        Assert.Contains(result.Findings, f => f.Id == "LW.SOURCE.KNOWN_MARKER");
        Assert.Equal(1, result.Metrics["nestedArchivesInspected"]);
    }

    [Fact]
    public async Task OpaqueRar_StrictDirectScan_IsIncomplete()
    {
        string path = Path.Combine(_root, "sample.rar");
        await File.WriteAllBytesAsync(path, [0x52, 0x61, 0x72, 0x21]);
        ScanResult result = await Scan(path, new ArchiveScanner(strictUnsupportedDirectArchive: true));
        Assert.Single(result.Errors);
    }

    [Fact]
    public async Task OpaqueRar_NonStrictScan_IsOnlyCounted()
    {
        string path = Path.Combine(_root, "sample.rar");
        await File.WriteAllBytesAsync(path, [0x52, 0x61, 0x72, 0x21]);
        ScanResult result = await Scan(path, new ArchiveScanner());
        Assert.Empty(result.Errors);
        Assert.Equal(1, result.Metrics["opaqueArchivesObserved"]);
    }

    [Fact]
    public async Task MalformedZip_IsSuspicious()
    {
        string path = Path.Combine(_root, "broken.zip");
        await File.WriteAllTextAsync(path, "not a zip");
        ScanResult result = await Scan(path, new ArchiveScanner());
        Assert.Contains(result.Findings, f => f.Id == "LG.ARCHIVE.INVALID_ZIP");
    }


    [Fact]
    public async Task ArchiveContainerSizeLimit_RefusesOpen()
    {
        string zip = CreateZip(("readme.txt", "hello world"));
        ScanResult result = await Scan(zip, new ArchiveScanner(), new ScanOptions { MaxFileBytes = 1 });
        Assert.Contains(result.Errors, e => e.Scanner == "ArchiveScanner" && e.Message.Contains("file-size limit", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, result.Metrics["archiveContainersSkipped"]);
    }

    [Fact]
    public async Task CleanZip_ReturnsClean()
    {
        string zip = CreateZip(("readme.txt", "hello world"));
        ScanResult result = await Scan(zip, new ArchiveScanner());
        Assert.Equal(Verdict.Clean, result.Verdict);
        Assert.Empty(result.Findings);
    }

    private async Task<ScanResult> Scan(string path, ArchiveScanner scanner, ScanOptions? options = null)
    {
        var target = new ScanTarget(ScanTargetKind.File, path);
        return await new ScanCoordinator([scanner]).ScanAsync(target, options);
    }

    private string CreateZip(params (string Name, string Content)[] entries)
    {
        string path = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".zip");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var item in entries)
        {
            ZipArchiveEntry entry = archive.CreateEntry(item.Name, CompressionLevel.Optimal);
            using var writer = new StreamWriter(entry.Open());
            writer.Write(item.Content);
        }
        return path;
    }

    private string CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        string path = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".zip");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var item in entries)
        {
            ZipArchiveEntry entry = archive.CreateEntry(item.Name, CompressionLevel.Optimal);
            using Stream output = entry.Open();
            output.Write(item.Content);
        }
        return path;
    }

    private static byte[] BuildPeBytes(string sectionName, uint characteristics, uint entryPoint)
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

    private static byte[] BuildZipBytes(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var item in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(item.Name, CompressionLevel.Optimal);
                using var writer = new StreamWriter(entry.Open());
                writer.Write(item.Content);
            }
        }
        return ms.ToArray();
    }
}
