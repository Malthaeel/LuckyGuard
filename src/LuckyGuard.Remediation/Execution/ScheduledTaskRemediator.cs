using System.Xml.Linq;

namespace LuckyGuard.Remediation.Execution;

internal static class ScheduledTaskRemediator
{
    public static ScheduledTaskBackup DeleteWithBackup(string taskPath, string executionDirectory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Scheduled Task remediation is Windows-only.");
        ValidateTaskPath(taskPath);
        Directory.CreateDirectory(executionDirectory);
        var query = ProcessCommandRunner.Run("schtasks.exe", "/Query", "/TN", taskPath, "/XML");
        if (query.ExitCode != 0 || string.IsNullOrWhiteSpace(query.StdOut))
            throw new InvalidOperationException($"Could not export Scheduled Task XML: {Clean(query.StdErr)}");
        if (!CanRestoreWithoutSecret(query.StdOut))
            throw new InvalidOperationException("Task uses a password-backed logon and cannot be safely auto-deleted because rollback would require a secret LuckyGuard does not collect.");

        string backupFile = Path.Combine(executionDirectory, $"task-{Guid.NewGuid():N}.xml");
        File.WriteAllText(backupFile, query.StdOut);
        var delete = ProcessCommandRunner.Run("schtasks.exe", "/Delete", "/TN", taskPath, "/F");
        if (delete.ExitCode != 0)
        {
            TryDelete(backupFile);
            throw new InvalidOperationException($"Could not delete Scheduled Task: {Clean(delete.StdErr)} {Clean(delete.StdOut)}".Trim());
        }
        return new ScheduledTaskBackup { TaskPath = taskPath, XmlBackupFile = backupFile, Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(backupFile))) };
    }

    public static void Restore(ScheduledTaskBackup backup)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Scheduled Task rollback is Windows-only.");
        ValidateTaskPath(backup.TaskPath);
        if (!File.Exists(backup.XmlBackupFile)) throw new FileNotFoundException("Scheduled Task XML backup is missing.", backup.XmlBackupFile);
        string actualHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(backup.XmlBackupFile)));
        if (!actualHash.Equals(backup.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Scheduled Task backup hash mismatch; rollback refused.");
        // Refuse overwrite: if the task already exists, rollback must not clobber it.
        var existing = ProcessCommandRunner.Run("schtasks.exe", "/Query", "/TN", backup.TaskPath);
        if (existing.ExitCode == 0) throw new IOException("Rollback target Scheduled Task already exists; LuckyGuard will not overwrite it.");
        var create = ProcessCommandRunner.Run("schtasks.exe", "/Create", "/TN", backup.TaskPath, "/XML", backup.XmlBackupFile, "/F");
        if (create.ExitCode != 0) throw new InvalidOperationException($"Could not restore Scheduled Task: {Clean(create.StdErr)} {Clean(create.StdOut)}".Trim());
    }

    internal static bool CanRestoreWithoutSecret(string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml, LoadOptions.None);
            return !doc.Descendants().Any(e => e.Name.LocalName.Equals("LogonType", StringComparison.OrdinalIgnoreCase)
                && e.Value.Trim().Contains("Password", StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private static void ValidateTaskPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 1024 || path.Contains('\0')) throw new ArgumentException("Invalid task path.", nameof(path));
        if (!path.StartsWith('\\')) throw new ArgumentException("Scheduled Task path must be absolute (begin with \\).", nameof(path));
    }
    private static string Clean(string text) => text.Replace('\r',' ').Replace('\n',' ').Trim();
    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }
}
