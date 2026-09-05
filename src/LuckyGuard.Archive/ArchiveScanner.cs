using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Scanning;
using LuckyGuard.Ioc.Store;
using LuckyGuard.PE.Analysis;
using LuckyGuard.Source;

namespace LuckyGuard.Archive;

public sealed class ArchiveScanner(
    IocStore? store = null,
    string? feedVersion = null,
    ArchiveScanLimits? limits = null,
    bool strictUnsupportedDirectArchive = false,
    bool reportOpaqueSummary = true) : IScanner
{
    private static readonly HashSet<string> ZipExtensions = new(StringComparer.OrdinalIgnoreCase) { ".zip", ".jar", ".nupkg" };
    private static readonly HashSet<string> OpaqueExtensions = new(StringComparer.OrdinalIgnoreCase) { ".rar", ".7z" };
    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".scr", ".cpl" };
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".c", ".cc", ".cpp", ".h", ".hpp", ".inl", ".props", ".targets", ".vcxproj", ".csproj", ".fsproj", ".vbproj", ".rsp", ".txt", ".ps1", ".bat", ".cmd", ".js", ".vbs" };
    private static readonly HashSet<string> HashExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".sys", ".scr", ".cpl", ".com", ".msi", ".bin", ".dat", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".zip", ".jar", ".nupkg", ".rar", ".7z" };

    private readonly IocStore _store = store ?? new IocStore();
    private readonly ArchiveScanLimits _limits = limits ?? new ArchiveScanLimits();
    public string Name => "ArchiveScanner";

    public bool CanScan(ScanTarget target) => target.Kind is ScanTargetKind.File or ScanTargetKind.Path or ScanTargetKind.Solution or ScanTargetKind.Project;

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        int archives = 0, entries = 0, contentScans = 0, nested = 0, opaque = 0, containersSkipped = 0;
        foreach (string archivePath in EnumerateCandidates(context, result))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            string ext = Path.GetExtension(archivePath);
            if (OpaqueExtensions.Contains(ext))
            {
                opaque++;
                if (strictUnsupportedDirectArchive && context.Target.Kind == ScanTargetKind.File && Path.GetFullPath(context.Target.FullPath).Equals(Path.GetFullPath(archivePath), StringComparison.OrdinalIgnoreCase))
                    result.Errors.Add(new ScanError(Name, $"Deep inspection of {ext} archives is not available in Phase 8. ZIP/JAR/NUPKG are inspected with decompression limits.", archivePath));
                continue;
            }

            if (!ZipExtensions.Contains(ext)) continue;
            try
            {
                var archiveInfo = new FileInfo(archivePath);
                if (archiveInfo.Length > context.Options.MaxFileBytes)
                {
                    containersSkipped++;
                    result.Errors.Add(new ScanError(Name, $"Archive container exceeds the configured file-size limit ({context.Options.MaxFileBytes} bytes) and was not opened.", archivePath));
                    continue;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (context.Target.Kind == ScanTargetKind.File || !context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError(Name, ex.Message, archivePath));
                continue;
            }
            archives++;
            try
            {
                using ZipArchive archive = ZipFile.OpenRead(archivePath);
                var state = new ArchiveState();
                InspectArchive(archive, archivePath, 0, state, result, context.CancellationToken);
                entries += state.Entries;
                contentScans += state.ContentScans;
                nested += state.NestedArchives;
            }
            catch (InvalidDataException ex)
            {
                result.Findings.Add(new DetectionFinding(
                    "LG.ARCHIVE.INVALID_ZIP", "Malformed ZIP-compatible archive", DetectionCategory.Archive,
                    DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                    "The archive could not be parsed as a valid ZIP-compatible container. Malformed archives can be benign corruption or intentionally evasive content.",
                    archivePath, [new Evidence("error", Truncate(ex.Message, 180))]));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (context.Target.Kind == ScanTargetKind.File || !context.Options.IgnoreInaccessible)
                    result.Errors.Add(new ScanError(Name, ex.Message, archivePath));
            }
        }

        result.Metrics["archivesAnalyzed"] = archives;
        result.Metrics["archiveEntriesInspected"] = entries;
        result.Metrics["archiveEntryContentScans"] = contentScans;
        result.Metrics["nestedArchivesInspected"] = nested;
        result.Metrics["opaqueArchivesObserved"] = opaque;
        result.Metrics["archiveContainersSkipped"] = containersSkipped;
        if (opaque > 0)
        {
            result.Notes.Add($"Observed {opaque} RAR/7Z archive(s). Phase 8 does not decompress those formats; ZIP/JAR/NUPKG receive bounded deep inspection.");
            bool strictDirectOpaque = strictUnsupportedDirectArchive && context.Target.Kind == ScanTargetKind.File && OpaqueExtensions.Contains(Path.GetExtension(context.Target.FullPath));
            if (reportOpaqueSummary && !strictDirectOpaque)
            {
                result.Findings.Add(new DetectionFinding(
                    "LG.ARCHIVE.OPAQUE_FORMAT", "Archive format observed without deep decompression", DetectionCategory.Archive,
                    DetectionSeverity.Informational, DetectionConfidence.Heuristic,
                    $"LuckyGuard observed {opaque} RAR/7Z archive(s). These formats are counted but not decompressed in Phase 8, so archive-content coverage is partial.", context.Target.Value,
                    [new Evidence("opaqueArchives", opaque.ToString())]));
            }
        }
        if (archives > 0) result.Notes.Add("Archive inspection is read-only and enforces entry-count, declared-size, compression-ratio, per-entry, and nested-depth limits before opening untrusted content.");
        if (archives > 0 && result.Findings.Count == 0 && result.Errors.Count == 0 && result.Verdict == Verdict.NotAssessed) result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }

    private void InspectArchive(ZipArchive archive, string displayPath, int depth, ArchiveState state, ScanResult result, CancellationToken cancellationToken)
    {
        if (depth > _limits.MaxNestedDepth) return;
        if (archive.Entries.Count > _limits.MaxEntries)
        {
            result.Findings.Add(new DetectionFinding(
                "LG.ARCHIVE.ENTRY_LIMIT", "Archive exceeds safe entry-count limit", DetectionCategory.Archive,
                DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                $"Archive declares {archive.Entries.Count} entries, exceeding LuckyGuard's {_limits.MaxEntries} entry safety limit. Content scanning stopped for this archive.", displayPath));
            return;
        }

        long totalDeclared = 0;
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            state.Entries++;
            if (string.IsNullOrEmpty(entry.Name)) continue;
            string entryPath = $"{displayPath}!{entry.FullName}";

            if (ArchivePathPolicy.IsTraversalLike(entry.FullName))
            {
                result.Findings.Add(new DetectionFinding(
                    "LG.ARCHIVE.PATH_TRAVERSAL", "Archive entry contains traversal-like path", DetectionCategory.Archive,
                    DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                    "The archive contains an absolute or parent-directory entry path. LuckyGuard never extracts entries using archive-provided paths.", entryPath,
                    [new Evidence("entry", Truncate(entry.FullName, 240))]));
            }

            totalDeclared = SaturatingAdd(totalDeclared, entry.Length);
            if (totalDeclared > _limits.MaxDeclaredUncompressedBytes)
            {
                result.Findings.Add(new DetectionFinding(
                    "LG.ARCHIVE.TOTAL_SIZE_LIMIT", "Archive exceeds safe decompression budget", DetectionCategory.Archive,
                    DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                    $"Declared uncompressed content exceeded {_limits.MaxDeclaredUncompressedBytes} bytes. Remaining entry content was not decompressed.", displayPath));
                break;
            }

            if (entry.Length > _limits.MaxEntryScanBytes)
            {
                result.Findings.Add(new DetectionFinding(
                    "LG.ARCHIVE.ENTRY_SIZE_LIMIT", "Archive entry exceeds per-entry scan budget", DetectionCategory.Archive,
                    DetectionSeverity.Low, DetectionConfidence.Heuristic,
                    $"Entry declares {entry.Length} uncompressed bytes and was not decompressed by LuckyGuard.", entryPath));
                continue;
            }

            if (entry.Length >= 10L * 1024 * 1024)
            {
                long compressed = Math.Max(entry.CompressedLength, 1);
                long ratio = entry.Length / compressed;
                if (ratio > _limits.MaxCompressionRatio)
                {
                    result.Findings.Add(new DetectionFinding(
                        "LG.ARCHIVE.HIGH_COMPRESSION_RATIO", "Archive entry has extreme compression ratio", DetectionCategory.Archive,
                        DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                        $"Entry compression ratio is approximately {ratio}:1, above LuckyGuard's {_limits.MaxCompressionRatio}:1 safety threshold. Entry content was not opened.", entryPath));
                    continue;
                }
            }

            MatchFilenameIoc(entry, entryPath, result);
            string ext = Path.GetExtension(entry.Name);

            if (_store.Count > 0 && (HashExtensions.Contains(ext) || PeExtensions.Contains(ext)))
            {
                try
                {
                    using Stream hashStream = entry.Open();
                    string sha256 = Convert.ToHexString(SHA256.HashData(hashStream)).ToLowerInvariant();
                    state.ContentScans++;
                    if (_store.TryMatch(IocType.Sha256, sha256, out var hashIoc) && hashIoc is not null)
                    {
                        result.Findings.Add(new DetectionFinding(
                            "LW.ARCHIVE.IOC_SHA256", "Known LuckyWare SHA-256 found inside archive", DetectionCategory.IOC,
                            IocSeverityMapper.ForDirectMatch(hashIoc.Confidence), hashIoc.Confidence,
                            "An archive entry's decompressed bytes exactly match a SHA-256 indicator in the verified LuckyGuard IOC feed.", entryPath,
                            [new Evidence("sha256", sha256), new Evidence("iocId", hashIoc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", hashIoc.Source)]));
                    }
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException) { MarkUnreadable(state, result, entryPath, ex); }
            }

            if (PeExtensions.Contains(ext))
            {
                try
                {
                    byte[] bytes = ReadBounded(entry, checked((int)Math.Min(entry.Length, _limits.MaxEntryScanBytes)));
                    state.ContentScans++;
                    result.Findings.AddRange(new PeFileAnalyzer().AnalyzeBytes(bytes, entryPath));
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException) { MarkUnreadable(state, result, entryPath, ex); }
                continue;
            }

            if (TextExtensions.Contains(ext) && entry.Length <= _limits.MaxTextScanBytes)
            {
                try
                {
                    string text = ReadTextBounded(entry, checked((int)Math.Min(entry.Length, _limits.MaxTextScanBytes)));
                    state.ContentScans++;
                    result.Findings.AddRange(new SourceFileAnalyzer().AnalyzeText(text, entryPath));
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException) { MarkUnreadable(state, result, entryPath, ex); }
                continue;
            }

            if (ZipExtensions.Contains(ext) && depth < _limits.MaxNestedDepth && entry.Length <= _limits.MaxEntryScanBytes)
            {
                try
                {
                    byte[] bytes = ReadBounded(entry, checked((int)Math.Min(entry.Length, _limits.MaxEntryScanBytes)));
                    using var ms = new MemoryStream(bytes, writable: false);
                    using var nestedArchive = new ZipArchive(ms, ZipArchiveMode.Read, leaveOpen: false);
                    state.NestedArchives++;
                    InspectArchive(nestedArchive, entryPath, depth + 1, state, result, cancellationToken);
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException) { MarkUnreadable(state, result, entryPath, ex); }
            }
        }
    }

    private static void MarkUnreadable(ArchiveState state, ScanResult result, string entryPath, Exception ex)
    {
        if (!state.UnreadableEntries.Add(entryPath)) return;
        result.Errors.Add(new ScanError("ArchiveScanner", $"Archive entry could not be read safely: {Truncate(ex.Message, 180)}", entryPath));
    }

    private void MatchFilenameIoc(ZipArchiveEntry entry, string entryPath, ScanResult result)
    {
        if (_store.Count == 0 || !_store.TryMatch(IocType.FileName, entry.Name, out var ioc) || ioc is null) return;
        result.Findings.Add(new DetectionFinding(
            "LW.ARCHIVE.IOC_FILENAME", "LuckyWare-associated filename found inside archive", DetectionCategory.IOC,
            IocSeverityMapper.ForFilenameMatch(ioc.Confidence), ioc.Confidence,
            "An archive entry name exactly matches an indicator in the verified LuckyGuard IOC feed. Filename matches are supporting evidence and are not treated like exact hash matches.", entryPath,
            [new Evidence("fileName", entry.Name), new Evidence("iocId", ioc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", ioc.Source)]));
    }

    private static byte[] ReadBounded(ZipArchiveEntry entry, int maxBytes)
    {
        using Stream input = entry.Open();
        using var output = new MemoryStream(Math.Min(maxBytes, 1024 * 1024));
        byte[] buffer = new byte[16 * 1024];
        int total = 0;
        while (true)
        {
            int read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            total += read;
            if (total > maxBytes) throw new InvalidDataException("Archive entry exceeded the bounded read budget.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static string ReadTextBounded(ZipArchiveEntry entry, int maxBytes)
    {
        byte[] bytes = ReadBounded(entry, maxBytes);
        return Encoding.UTF8.GetString(bytes);
    }

    private static long SaturatingAdd(long left, long right) => right > long.MaxValue - left ? long.MaxValue : left + right;
    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max] + "...";

    private static IEnumerable<string> EnumerateCandidates(ScanContext context, ScanResult result)
    {
        string target = context.Target.FullPath;
        if (File.Exists(target))
        {
            string ext = Path.GetExtension(target);
            if (ZipExtensions.Contains(ext) || OpaqueExtensions.Contains(ext)) yield return target;
            yield break;
        }
        if (!Directory.Exists(target)) yield break;

        var stack = new Stack<string>();
        stack.Push(target);
        int visited = 0;
        while (stack.Count > 0)
        {
            string dir = stack.Pop();
            IEnumerable<string> files;
            IEnumerable<string> dirs;
            try { files = Directory.EnumerateFiles(dir); dirs = Directory.EnumerateDirectories(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("ArchiveScanner", ex.Message, dir));
                continue;
            }
            foreach (string file in files)
            {
                if (++visited > context.Options.MaxFiles) yield break;
                string ext = Path.GetExtension(file);
                if (ZipExtensions.Contains(ext) || OpaqueExtensions.Contains(ext)) yield return file;
            }
            foreach (string child in dirs)
            {
                try
                {
                    if (!context.Options.FollowReparsePoints && File.GetAttributes(child).HasFlag(FileAttributes.ReparsePoint)) continue;
                    stack.Push(child);
                }
                catch { }
            }
        }
    }

    private sealed class ArchiveState
    {
        public int Entries;
        public int ContentScans;
        public int NestedArchives;
        public HashSet<string> UnreadableEntries { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
