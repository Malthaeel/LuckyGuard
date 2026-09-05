using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Scanning;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Tests;

public sealed class FileIocScannerTests
{
    [Fact]
    public async Task CommunityFilenameOnly_IsSuspiciousNotHigh()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, "Berok.exe");
        await File.WriteAllBytesAsync(file, [0x4D, 0x5A, 0x00, 0x00]);
        try
        {
            var store = new IocStore();
            store.Add(new IocEntry("berok", IocType.FileName, "Berok.exe", DetectionConfidence.Community, "test"));
            var scanner = new FileIocScanner(store, "test");
            var target = new ScanTarget(ScanTargetKind.File, file);
            var result = new ScanResult { Target = target };
            await scanner.ScanAsync(new ScanContext(target, new ScanOptions(), CancellationToken.None), result);
            var finding = Assert.Single(result.Findings, x => x.Id == "LW.IOC.FILENAME_MATCH");
            Assert.Equal(DetectionSeverity.Suspicious, finding.Severity);
        }
        finally { Directory.Delete(dir, true); }
    }
}
