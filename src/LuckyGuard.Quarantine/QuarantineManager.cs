using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.Quarantine;

public sealed class QuarantineManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public string RootPath { get; }

    public QuarantineManager(string? rootPath = null)
    {
        RootPath = Path.GetFullPath(rootPath ?? GetDefaultRoot());
    }

    public QuarantineEntry QuarantineFile(string sourcePath, IEnumerable<string> findingIds, DetectionSeverity severity, DetectionConfidence confidence)
    {
        string fullSource = Path.GetFullPath(sourcePath);
        if (IsUnderRoot(fullSource, RootPath)) throw new InvalidOperationException("LuckyGuard refuses to quarantine a file already inside its quarantine root.");
        if (!File.Exists(fullSource)) throw new FileNotFoundException("Quarantine source file does not exist.", fullSource);

        FileAttributes attributes = File.GetAttributes(fullSource);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException("LuckyGuard refuses to quarantine a reparse-point file target.");

        Directory.CreateDirectory(RootPath);
        string id = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
        string entryDir = Path.Combine(RootPath, id);
        Directory.CreateDirectory(entryDir);
        string storedPath = Path.Combine(entryDir, "payload.lgq");
        string metadataPath = Path.Combine(entryDir, "metadata.json");

        string beforeHash = ComputeSha256(fullSource);
        long size = new FileInfo(fullSource).Length;

        // Copy -> verify -> delete is intentionally used instead of a blind move so
        // quarantine integrity is known before the original is removed.
        File.Copy(fullSource, storedPath, overwrite: false);
        string storedHash = ComputeSha256(storedPath);
        if (!string.Equals(beforeHash, storedHash, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(storedPath);
            Directory.Delete(entryDir, recursive: true);
            throw new IOException("Quarantine copy hash verification failed; original file was left untouched.");
        }

        string finalSourceHash = ComputeSha256(fullSource);
        if (!string.Equals(finalSourceHash, storedHash, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(storedPath);
            Directory.Delete(entryDir, recursive: true);
            throw new IOException("Source changed while quarantine was being prepared; original file was left untouched.");
        }

        var entry = new QuarantineEntry
        {
            Id = id,
            OriginalPath = fullSource,
            StoredPath = storedPath,
            Sha256 = beforeHash,
            Size = size,
            QuarantinedAtUtc = DateTimeOffset.UtcNow,
            Severity = severity,
            Confidence = confidence,
            FindingIds = findingIds.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList()
        };

        File.WriteAllText(metadataPath, JsonSerializer.Serialize(entry, JsonOptions));
        File.Delete(fullSource);
        return entry;
    }

    public IReadOnlyList<QuarantineEntry> List()
    {
        if (!Directory.Exists(RootPath)) return [];
        var entries = new List<QuarantineEntry>();
        foreach (string dir in Directory.EnumerateDirectories(RootPath))
        {
            string metadata = Path.Combine(dir, "metadata.json");
            if (!File.Exists(metadata)) continue;
            try
            {
                var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metadata), JsonOptions);
                if (entry is not null) entries.Add(entry);
            }
            catch { }
        }
        return entries.OrderByDescending(e => e.QuarantinedAtUtc).ToArray();
    }

    public QuarantineEntry Get(string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || id.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException("Invalid quarantine id.", nameof(id));
        string metadata = Path.Combine(RootPath, id, "metadata.json");
        if (!File.Exists(metadata)) throw new FileNotFoundException("Quarantine entry was not found.", metadata);
        var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metadata), JsonOptions)
                    ?? throw new InvalidDataException("Quarantine metadata is invalid.");
        string expectedStored = Path.GetFullPath(Path.Combine(RootPath, id, "payload.lgq"));
        if (!entry.Id.Equals(id, StringComparison.Ordinal)
            || !Path.GetFullPath(entry.StoredPath).Equals(expectedStored, StringComparison.OrdinalIgnoreCase)
            || !Path.IsPathRooted(entry.OriginalPath))
            throw new InvalidDataException("Quarantine metadata path validation failed.");
        return entry;
    }

    public string Restore(string id)
    {
        QuarantineEntry entry = Get(id);
        if (!File.Exists(entry.StoredPath)) throw new FileNotFoundException("Quarantined payload is missing.", entry.StoredPath);
        if (File.Exists(entry.OriginalPath)) throw new IOException("Original path is already occupied; LuckyGuard will not overwrite it.");
        if (!string.Equals(ComputeSha256(entry.StoredPath), entry.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Quarantine payload hash no longer matches metadata.");

        string? parent = Path.GetDirectoryName(entry.OriginalPath);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
        File.Copy(entry.StoredPath, entry.OriginalPath, overwrite: false);
        if (!string.Equals(ComputeSha256(entry.OriginalPath), entry.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(entry.OriginalPath);
            throw new IOException("Restored file failed hash verification.");
        }
        return entry.OriginalPath;
    }

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static bool IsUnderRoot(string path, string root)
    {
        string fullPath = Path.GetFullPath(path);
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
    }

    private static string GetDefaultRoot()
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(programData)) programData = Path.GetTempPath();
        return Path.Combine(programData, "LuckyGuard", "Quarantine");
    }
}
