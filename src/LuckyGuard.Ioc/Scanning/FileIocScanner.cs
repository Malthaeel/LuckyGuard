using System.Security.Cryptography;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Ioc.Scanning;

public sealed class FileIocScanner(IocStore store, string? feedVersion = null) : IScanner
{
    private static readonly HashSet<string> HashExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".sys", ".scr", ".cpl", ".com", ".msi", ".bin", ".dat", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".zip", ".rar", ".7z" };

    public string Name => "FileIocScanner";
    public bool CanScan(ScanTarget target) => target.Kind != ScanTargetKind.System;

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        if (store.Count == 0)
        {
            result.Errors.Add(new ScanError(Name, "Verified IOC feed is empty or unavailable.", result.Target.Value));
            return Task.CompletedTask;
        }

        int names = 0, hashes = 0, visited = 0;
        foreach (string file in EnumerateFiles(context, result))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (++visited > context.Options.MaxFiles) break;

            string fileName = Path.GetFileName(file);
            if (store.TryMatch(IocType.FileName, fileName, out var nameIoc) && nameIoc is not null)
            {
                names++;
                result.Findings.Add(new DetectionFinding(
                    "LW.IOC.FILENAME_MATCH", "LuckyWare-associated filename IOC matched", DetectionCategory.IOC,
                    IocSeverityMapper.ForFilenameMatch(nameIoc.Confidence), nameIoc.Confidence,
                    "The file name exactly matches an indicator in the verified LuckyGuard IOC feed. Filename matches are supporting evidence and should be correlated with file content and context.",
                    file,
                    [new Evidence("fileName", fileName), new Evidence("iocId", nameIoc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", nameIoc.Source)]));
            }

            string ext = Path.GetExtension(file);
            if (!HashExtensions.Contains(ext) && context.Target.Kind != ScanTargetKind.File) continue;
            try
            {
                var info = new FileInfo(file);
                if (info.Length <= 0 || info.Length > context.Options.MaxFileBytes) continue;
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                string sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
                hashes++;
                if (store.TryMatch(IocType.Sha256, sha256, out var hashIoc) && hashIoc is not null)
                {
                    result.Findings.Add(new DetectionFinding(
                        "LW.IOC.SHA256_MATCH", "Known LuckyWare SHA-256 matched", DetectionCategory.IOC,
                        IocSeverityMapper.ForDirectMatch(hashIoc.Confidence), hashIoc.Confidence,
                        "The file SHA-256 exactly matches an indicator in the verified LuckyGuard IOC feed.", file,
                        [new Evidence("sha256", sha256), new Evidence("iocId", hashIoc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", hashIoc.Source)]));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError(Name, ex.Message, file));
            }
        }

        result.Metrics["iocFilesVisited"] = visited;
        result.Metrics["iocFileNamesMatched"] = names;
        result.Metrics["iocHashesComputed"] = hashes;
        result.Notes.Add($"IOC file matching used verified feed {feedVersion ?? "unknown"}; exact hashes are stronger evidence than filename-only indicators.");
        return Task.CompletedTask;
    }

    private static IEnumerable<string> EnumerateFiles(ScanContext context, ScanResult result)
    {
        string target = context.Target.FullPath;
        if (context.Target.Kind == ScanTargetKind.File && File.Exists(target)) { yield return target; yield break; }

        string? root = Directory.Exists(target) ? target : Path.GetDirectoryName(target);
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) yield break;

        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            string dir = stack.Pop();
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError("FileIocScanner", ex.Message, dir));
                continue;
            }
            foreach (string file in files) yield return file;

            IEnumerable<string> dirs;
            try { dirs = Directory.EnumerateDirectories(dir); }
            catch { continue; }
            foreach (string child in dirs)
            {
                try
                {
                    var attr = File.GetAttributes(child);
                    if (!context.Options.FollowReparsePoints && attr.HasFlag(FileAttributes.ReparsePoint)) continue;
                    stack.Push(child);
                }
                catch { }
            }
        }
    }
}
