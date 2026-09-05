using System.Diagnostics;

namespace LuckyGuard.Guard;

public sealed class GuardServiceManager
{
    public const string ServiceName = "LuckyGuardGuard";
    public const string DisplayName = "LuckyGuard Realtime Guard";
    public static string ServiceInstallDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LuckyGuard", "Service");
    public static string InstalledServiceExecutable => Path.Combine(ServiceInstallDirectory, "LuckyGuardService.exe");

    public static string? LocateServiceExecutable(string? repositoryRoot = null)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(repositoryRoot))
        {
            string root = Path.GetFullPath(repositoryRoot);
            candidates.Add(Path.Combine(root, "src", "LuckyGuard.Service", "bin", "Release", "net9.0", "LuckyGuardService.exe"));
            candidates.Add(Path.Combine(root, "src", "LuckyGuard.Service", "bin", "Debug", "net9.0", "LuckyGuardService.exe"));
        }
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "LuckyGuardService.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "service", "LuckyGuardService.exe"));
        return candidates.FirstOrDefault(File.Exists);
    }

    public async Task<GuardServiceCommandResult> InstallAsync(string executablePath, GuardServiceConfig config, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) return new(false, -1, string.Empty, "LuckyGuard Guard service is Windows-only.");
        string fullExe = Path.GetFullPath(executablePath);
        if (!File.Exists(fullExe)) return new(false, -1, string.Empty, $"Service executable was not found: {fullExe}");
        string deployedExe;
        try { deployedExe = DeployServiceFiles(fullExe); }
        catch (Exception ex) { return new(false, -1, string.Empty, $"Service host deployment failed: {ex.Message}"); }
        GuardServiceConfigStore.Save(config);

        var create = await RunScAsync(BuildCreateArguments(deployedExe), cancellationToken);
        if (!create.Success)
        {
            if (!create.Combined.Contains("1073", StringComparison.OrdinalIgnoreCase)) return create;
            GuardServiceCommandResult configExisting = await RunScAsync(["config", ServiceName, "binPath=", $"\"{deployedExe}\" --service", "start=", "auto", "DisplayName=", DisplayName], cancellationToken);
            if (!configExisting.Success) return configExisting;
        }

        await RunScAsync(["description", ServiceName, "LuckyGuard alert-only realtime file/network protection service."], cancellationToken);
        await RunScAsync(["failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000"], cancellationToken);
        return new(true, 0, create.StandardOutput, create.StandardError);
    }

    public Task<GuardServiceCommandResult> StartAsync(CancellationToken cancellationToken = default) => RunScAsync(["start", ServiceName], cancellationToken);
    public Task<GuardServiceCommandResult> StopAsync(CancellationToken cancellationToken = default) => RunScAsync(["stop", ServiceName], cancellationToken);
    public Task<GuardServiceCommandResult> QueryAsync(CancellationToken cancellationToken = default) => RunScAsync(["query", ServiceName], cancellationToken);

    public async Task<GuardServiceCommandResult> UninstallAsync(CancellationToken cancellationToken = default)
    {
        GuardServiceCommandResult stop = await StopAsync(cancellationToken);
        _ = stop;
        return await RunScAsync(["delete", ServiceName], cancellationToken);
    }

    internal static string DeployServiceFiles(string executablePath)
    {
        string sourceExe = Path.GetFullPath(executablePath);
        string sourceDir = Path.GetDirectoryName(sourceExe) ?? throw new InvalidOperationException("Service source directory is unavailable.");
        Directory.CreateDirectory(ServiceInstallDirectory);
        string installRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(ServiceInstallDirectory));
        string installPrefix = installRoot + Path.DirectorySeparatorChar;
        foreach (string source in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(sourceDir, source);
            if (relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative))
                throw new InvalidDataException("Service deployment produced an unsafe relative path.");
            string destination = Path.GetFullPath(Path.Combine(installRoot, relative));
            if (!destination.StartsWith(installPrefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Service deployment attempted to escape its ProgramData root.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination) ?? installRoot);
            File.Copy(source, destination, overwrite: true);
        }
        if (!File.Exists(InstalledServiceExecutable))
            throw new FileNotFoundException("Deployed LuckyGuardService.exe was not found after copy.", InstalledServiceExecutable);
        return InstalledServiceExecutable;
    }

    internal static IReadOnlyList<string> BuildCreateArguments(string executablePath) =>
        ["create", ServiceName, "binPath=", $"\"{Path.GetFullPath(executablePath)}\" --service", "start=", "auto", "DisplayName=", DisplayName];

    private static async Task<GuardServiceCommandResult> RunScAsync(IEnumerable<string> args, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) return new(false, -1, string.Empty, "sc.exe is available only on Windows.");
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string arg in args) psi.ArgumentList.Add(arg);
        using Process process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start sc.exe.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return new GuardServiceCommandResult(process.ExitCode == 0, process.ExitCode, await stdout, await stderr);
    }
}
