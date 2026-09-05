using LuckyGuard.Core.Detection;
using LuckyGuard.Quarantine;

namespace LuckyGuard.Tests;

public sealed class QuarantineManagerTests
{
    [Fact]
    public void Quarantine_ThenRestore_PreservesContentAndHash()
    {
        using var temp = new TestTempDirectory();
        string source = Path.Combine(temp.Path, "sample.exe");
        File.WriteAllBytes(source, [1,2,3,4,5,6]);
        var manager = new QuarantineManager(Path.Combine(temp.Path, "q"));

        var entry = manager.QuarantineFile(source, ["LW.IOC.SHA256_MATCH"], DetectionSeverity.Critical, DetectionConfidence.Confirmed);

        Assert.False(File.Exists(source));
        Assert.True(File.Exists(entry.StoredPath));
        Assert.Single(manager.List());
        string restored = manager.Restore(entry.Id);
        Assert.Equal(Path.GetFullPath(source), restored);
        Assert.Equal(new byte[] {1,2,3,4,5,6}, File.ReadAllBytes(source));
    }

    [Fact]
    public void Restore_RefusesToOverwriteExistingOriginal()
    {
        using var temp = new TestTempDirectory();
        string source = Path.Combine(temp.Path, "sample.exe");
        File.WriteAllText(source, "original");
        var manager = new QuarantineManager(Path.Combine(temp.Path, "q"));
        var entry = manager.QuarantineFile(source, ["LW.IOC.SHA256_MATCH"], DetectionSeverity.Critical, DetectionConfidence.Confirmed);
        File.WriteAllText(source, "replacement");

        Assert.Throws<IOException>(() => manager.Restore(entry.Id));
        Assert.Equal("replacement", File.ReadAllText(source));
    }


    [Fact]
    public void Get_RejectsTamperedStoredPathMetadata()
    {
        using var temp = new TestTempDirectory();
        string source = Path.Combine(temp.Path, "sample.exe");
        File.WriteAllText(source, "payload");
        var manager = new QuarantineManager(Path.Combine(temp.Path, "q"));
        var entry = manager.QuarantineFile(source, ["LW.IOC.SHA256_MATCH"], DetectionSeverity.Critical, DetectionConfidence.Confirmed);
        string metadata = Path.Combine(manager.RootPath, entry.Id, "metadata.json");
        string json = File.ReadAllText(metadata).Replace("payload.lgq", "other.lgq", StringComparison.Ordinal);
        File.WriteAllText(metadata, json);
        Assert.Throws<InvalidDataException>(() => manager.Get(entry.Id));
    }

    [Fact]
    public void Quarantine_RefusesFileAlreadyInsideQuarantineRoot()
    {
        using var temp = new TestTempDirectory();
        string root = Path.Combine(temp.Path, "q");
        Directory.CreateDirectory(root);
        string source = Path.Combine(root, "inside.exe");
        File.WriteAllText(source, "payload");
        var manager = new QuarantineManager(root);
        Assert.Throws<InvalidOperationException>(() => manager.QuarantineFile(source, ["X"], DetectionSeverity.High, DetectionConfidence.Confirmed));
        Assert.True(File.Exists(source));
    }

    [Fact]
    public void List_IgnoresInvalidMetadataDirectories()
    {
        using var temp = new TestTempDirectory();
        string root = Path.Combine(temp.Path, "q");
        Directory.CreateDirectory(Path.Combine(root, "broken"));
        File.WriteAllText(Path.Combine(root, "broken", "metadata.json"), "not-json");
        var manager = new QuarantineManager(root);
        Assert.Empty(manager.List());
    }
}

internal sealed class TestTempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
    public TestTempDirectory() => Directory.CreateDirectory(Path);
    public void Dispose() { try { Directory.Delete(Path, true); } catch { } }
}
