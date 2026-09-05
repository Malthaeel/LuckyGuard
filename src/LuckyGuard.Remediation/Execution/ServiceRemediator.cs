using System.Text.RegularExpressions;

namespace LuckyGuard.Remediation.Execution;

internal static partial class ServiceRemediator
{
    public static ServiceBackup DeleteWithBackup(string serviceName, string executionDirectory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Service remediation is Windows-only.");
        ValidateServiceName(serviceName);
        Directory.CreateDirectory(executionDirectory);

        var query = ProcessCommandRunner.Run("sc.exe", "query", serviceName);
        if (query.ExitCode != 0) throw new InvalidOperationException("Service no longer exists.");
        if (!query.StdOut.Contains("STATE", StringComparison.OrdinalIgnoreCase) || !query.StdOut.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("LuckyGuard will not auto-delete a running service. Stop/review it manually first.");

        string backupFile = Path.Combine(executionDirectory, $"service-{Guid.NewGuid():N}.reg");
        string registryPath = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}";
        var export = ProcessCommandRunner.Run("reg.exe", "export", registryPath, backupFile, "/y");
        if (export.ExitCode != 0 || !File.Exists(backupFile))
            throw new InvalidOperationException($"Could not back up service registry configuration: {Clean(export.StdErr)} {Clean(export.StdOut)}".Trim());

        var delete = ProcessCommandRunner.Run("sc.exe", "delete", serviceName);
        if (delete.ExitCode != 0)
        {
            TryDelete(backupFile);
            throw new InvalidOperationException($"Could not delete service: {Clean(delete.StdErr)} {Clean(delete.StdOut)}".Trim());
        }
        return new ServiceBackup { ServiceName = serviceName, RegistryBackupFile = backupFile, Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(backupFile))), RebootMayBeRequired = true };
    }

    public static void Restore(ServiceBackup backup)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Service rollback is Windows-only.");
        ValidateServiceName(backup.ServiceName);
        if (!File.Exists(backup.RegistryBackupFile)) throw new FileNotFoundException("Service registry backup is missing.", backup.RegistryBackupFile);
        string actualHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(backup.RegistryBackupFile)));
        if (!actualHash.Equals(backup.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Service registry backup hash mismatch; rollback refused.");
        var existing = ProcessCommandRunner.Run("sc.exe", "query", backup.ServiceName);
        if (existing.ExitCode == 0) throw new IOException("Rollback target service already exists; LuckyGuard will not overwrite it.");
        var import = ProcessCommandRunner.Run("reg.exe", "import", backup.RegistryBackupFile);
        if (import.ExitCode != 0) throw new InvalidOperationException($"Could not restore service registry backup: {Clean(import.StdErr)} {Clean(import.StdOut)}".Trim());
    }

    internal static void ValidateServiceName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || !ServiceNameRegex().IsMatch(name)) throw new ArgumentException("Invalid service name.", nameof(name));
    }

    [GeneratedRegex("^[A-Za-z0-9_.@{}$-]{1,256}$", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceNameRegex();
    private static string Clean(string text) => text.Replace('\r',' ').Replace('\n',' ').Trim();
    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }
}
