using LuckyGuard.Archive;
using System.Security.Principal;
using System.Text;
using LuckyGuard.Core;
using LuckyGuard.Core.Configuration;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Detection.Scoring;
using LuckyGuard.Defender;
using LuckyGuard.Ioc.Feed;
using LuckyGuard.Guard;
using LuckyGuard.Ioc.Scanning;
using LuckyGuard.Ioc.Store;
using LuckyGuard.PE;
using LuckyGuard.Quarantine;
using LuckyGuard.Remediation.Execution;
using LuckyGuard.Remediation.Models;
using LuckyGuard.Remediation.Planning;
using LuckyGuard.Remediation.Serialization;
using LuckyGuard.Reporting;
using LuckyGuard.SDK;
using LuckyGuard.Solution.Scanning;
using LuckyGuard.Suo;
using LuckyGuard.Windows.Network;
using LuckyGuard.Windows.Persistence;
using LuckyGuard.Windows.Processes;

namespace LuckyGuard.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                if (!Console.IsInputRedirected && !Console.IsOutputRedirected) return await RunInteractiveShellAsync();
                PrintHelp();
                return ExitCodes.Success;
            }
            if (IsHelp(args[0])) { PrintHelp(); return ExitCodes.Success; }
            if (args[0].Equals("--version", StringComparison.OrdinalIgnoreCase) || args[0].Equals("version", StringComparison.OrdinalIgnoreCase))
            { Console.WriteLine($"{BuildInfo.ProductName} {BuildInfo.Version}"); return ExitCodes.Success; }
            if (args[0].Equals("status", StringComparison.OrdinalIgnoreCase)) { PrintStatus(); return ExitCodes.Success; }
            if (args[0].Equals("update", StringComparison.OrdinalIgnoreCase)) return await RunProductUpdateAsync(args.Skip(1).ToArray());
            if (args[0].Equals("ioc", StringComparison.OrdinalIgnoreCase)) return await RunIocAsync(args.Skip(1).ToArray());
            if (args[0].Equals("defender", StringComparison.OrdinalIgnoreCase)) return await RunDefenderAsync(args.Skip(1).ToArray());
            if (args[0].Equals("guard", StringComparison.OrdinalIgnoreCase)) return await RunGuardAsync(args.Skip(1).ToArray());
            if (args[0].Equals("scan", StringComparison.OrdinalIgnoreCase)) return await RunScanAsync(args.Skip(1).ToArray());
            if (args[0].Equals("verify", StringComparison.OrdinalIgnoreCase)) return await RunVerifyAsync(args.Skip(1).ToArray());
            if (args[0].Equals("clean", StringComparison.OrdinalIgnoreCase)) return await RunCleanAsync(args.Skip(1).ToArray());
            if (args[0].Equals("quarantine", StringComparison.OrdinalIgnoreCase)) return RunQuarantine(args.Skip(1).ToArray());

            Console.Error.WriteLine($"Unknown command: {args[0]}");
            PrintHelp();
            return ExitCodes.Usage;
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Operation cancelled."); return ExitCodes.Incomplete; }
        catch (Exception ex) { Console.Error.WriteLine($"LuckyGuard internal error: {ex.Message}"); return ExitCodes.Failure; }
    }

    private static async Task<int> RunIocAsync(string[] args)
    {
        string action = args.Length == 0 ? "status" : args[0].ToLowerInvariant();
        if (action == "update") return await RunIocUpdateAsync(args.Skip(1).ToArray());
        if (action is not ("status" or "verify"))
        {
            Console.Error.WriteLine("Usage: LuckyGuard ioc <status|verify|update>");
            return ExitCodes.Usage;
        }

        var loaded = TryLoadIoc(out string? error);
        if (loaded is null)
        {
            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            Console.WriteLine("IOC feed : INVALID / UNAVAILABLE");
            Console.WriteLine($"Reason   : {error}");
            return ExitCodes.Incomplete;
        }

        Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
        Console.WriteLine(new string('─', 58));
        Console.WriteLine("IOC feed : VERIFIED");
        Console.WriteLine($"Version  : {loaded.Feed.FeedVersion}");
        Console.WriteLine($"Entries  : {loaded.Store.Count}");
        Console.WriteLine($"Generated: {loaded.Feed.GeneratedAtUtc:O}");
        Console.WriteLine($"Feed     : {loaded.FeedPath}");
        Console.WriteLine("Signature: ECDSA P-256 / SHA-256 / VERIFIED");
        foreach (var group in loaded.Feed.Entries.GroupBy(e => e.Confidence).OrderByDescending(g => g.Key))
            Console.WriteLine($"  {group.Key,-10}: {group.Count()}");
        return ExitCodes.Success;
    }

    private static async Task<int> RunIocUpdateAsync(string[] args)
    {
        string? feedUrl = GetOption(args, "--feed-url");
        string? sigUrl = GetOption(args, "--signature-url");
        if (string.IsNullOrWhiteSpace(feedUrl) && string.IsNullOrWhiteSpace(sigUrl))
        {
            PublicReleaseConfig? publicConfig = PublicReleaseConfig.LoadDefault();
            if (publicConfig is null || !publicConfig.HasOfficialIocEndpoint || !publicConfig.IsRepositoryConfigured)
            {
                Console.Error.WriteLine("Official LuckyGuard IOC endpoint is not configured in config/public-release.json.");
                Console.Error.WriteLine("Use explicit --feed-url/--signature-url for development, or configure the public repository first.");
                return ExitCodes.Incomplete;
            }
            feedUrl = publicConfig.IocFeedUrl;
            sigUrl = publicConfig.IocSignatureUrl;
        }
        if (string.IsNullOrWhiteSpace(feedUrl) || string.IsNullOrWhiteSpace(sigUrl)
            || !Uri.TryCreate(feedUrl, UriKind.Absolute, out var feedUri)
            || !Uri.TryCreate(sigUrl, UriKind.Absolute, out var sigUri))
        {
            Console.Error.WriteLine("Usage: LuckyGuard ioc update [--feed-url <https-url> --signature-url <https-url>]");
            Console.Error.WriteLine("Without URLs, LuckyGuard uses its configured official signed IOC endpoint.");
            return ExitCodes.Usage;
        }
        var bundled = IocFeedLoader.LocateBundled();
        if (bundled is null)
        {
            Console.Error.WriteLine("Bundled IOC feed/public-key files were not found; update cannot establish a pinned trust root.");
            return ExitCodes.Incomplete;
        }
        if (OperatingSystem.IsWindows() && !IsElevated())
        {
            Console.Error.WriteLine("System-wide IOC update requires an elevated Administrator terminal.");
            Console.Error.WriteLine("Re-open PowerShell as Administrator and run: luckyguard ioc update");
            return ExitCodes.Incomplete;
        }
        try
        {
            // Establish the shipped verified feed as the initial anti-rollback baseline in ProgramData.
            _ = IocFeedLoader.LoadVerified(bundled.Value.Feed, bundled.Value.Signature, bundled.Value.PublicKey);
            var destinations = IocFeedLoader.GetSystemUpdatePaths();
            Directory.CreateDirectory(Path.GetDirectoryName(destinations.Feed)!);
            bool systemBaselineValid = false;
            if (File.Exists(destinations.Feed) && File.Exists(destinations.Signature))
            {
                try
                {
                    _ = IocFeedLoader.LoadVerified(destinations.Feed, destinations.Signature, bundled.Value.PublicKey);
                    systemBaselineValid = true;
                }
                catch { systemBaselineValid = false; }
            }
            if (!systemBaselineValid)
            {
                File.Copy(bundled.Value.Feed, destinations.Feed, overwrite: true);
                File.Copy(bundled.Value.Signature, destinations.Signature, overwrite: true);
            }

            var update = await new IocFeedUpdater().UpdateAsync(feedUri, sigUri, destinations.Feed, destinations.Signature, bundled.Value.PublicKey);
            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            Console.WriteLine("IOC update : VERIFIED + INSTALLED");
            Console.WriteLine($"Version    : {update.FeedVersion}");
            Console.WriteLine($"Entries    : {update.Entries}");
            Console.WriteLine($"Feed       : {update.FeedPath}");
            return ExitCodes.Success;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IOC update rejected: {ex.Message}");
            Console.Error.WriteLine("Existing signed IOC feed was left in place or restored from backup.");
            return ExitCodes.Incomplete;
        }
    }

    private static async Task<int> RunProductUpdateAsync(string[] args)
    {
        string action = args.Length == 0 ? "check" : args[0].ToLowerInvariant();
        if (action != "check")
        {
            Console.Error.WriteLine("Usage: LuckyGuard update check");
            Console.Error.WriteLine("1.0 RC checks the official GitHub release channel but does not silently self-install application updates.");
            return ExitCodes.Usage;
        }

        PublicReleaseConfig? config = PublicReleaseConfig.LoadDefault();
        if (config is null || !config.IsRepositoryConfigured)
        {
            Console.Error.WriteLine("LuckyGuard public GitHub repository is not configured yet.");
            return ExitCodes.Incomplete;
        }

        try
        {
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("LuckyGuard-UpdateChecker/1.0");
            client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2026-03-10");
            using HttpResponseMessage response = await client.GetAsync($"https://api.github.com/repos/{config.Repository}/releases/latest");
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"GitHub update check failed: HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
                return ExitCodes.Incomplete;
            }
            using var doc = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = doc.RootElement;
            string latestTag = root.TryGetProperty("tag_name", out var tag) ? tag.GetString() ?? "<unknown>" : "<unknown>";
            bool draft = root.TryGetProperty("draft", out var draftEl) && draftEl.GetBoolean();
            bool prerelease = root.TryGetProperty("prerelease", out var preEl) && preEl.GetBoolean();
            if (draft || prerelease)
            {
                Console.Error.WriteLine("GitHub latest endpoint returned a non-stable release; refusing it as the stable update channel.");
                return ExitCodes.Incomplete;
            }

            bool newer = ReleaseVersionPolicy.IsNewerStableRelease(BuildInfo.Version, latestTag);
            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            Console.WriteLine($"Repository    : {config.Repository}");
            Console.WriteLine($"Current       : v{BuildInfo.Version}");
            Console.WriteLine($"Latest stable : {latestTag}");
            Console.WriteLine($"Update        : {(newer ? "AVAILABLE" : "not newer")}");
            Console.WriteLine("Install path  : use the signed GitHub installer / install.ps1 bootstrap; silent self-update is intentionally disabled in 1.0 RC.");
            return ExitCodes.Success;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Update check failed: {ex.Message}");
            return ExitCodes.Incomplete;
        }
    }

    private static async Task<int> RunDefenderAsync(string[] args)
    {
        string action = args.Length == 0 ? "status" : args[0].ToLowerInvariant();
        var bridge = new DefenderBridge();
        if (action == "status")
        {
            DefenderStatus status = await bridge.GetStatusAsync();
            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            if (!status.Available)
            {
                Console.WriteLine("Microsoft Defender: UNAVAILABLE");
                Console.WriteLine($"Reason: {status.Error}");
                return ExitCodes.Incomplete;
            }
            Console.WriteLine("Microsoft Defender: AVAILABLE");
            Console.WriteLine($"Antivirus          : {(status.AntivirusEnabled ? "ON" : "OFF")}");
            Console.WriteLine($"Real-time          : {(status.RealTimeProtectionEnabled ? "ON" : "OFF")}");
            Console.WriteLine($"Behavior monitor   : {(status.BehaviorMonitorEnabled ? "ON" : "OFF")}");
            Console.WriteLine($"Download protection: {(status.IoavProtectionEnabled ? "ON" : "OFF")}");
            Console.WriteLine($"Signature version  : {status.AntivirusSignatureVersion ?? "<unknown>"}");
            Console.WriteLine($"Signature updated  : {(status.AntivirusSignatureLastUpdated?.ToString("O") ?? "<unknown>")}");
            return status.AntivirusEnabled && status.RealTimeProtectionEnabled ? ExitCodes.Success : ExitCodes.Suspicious;
        }

        if (action is "quick" or "full")
        {
            if (!OperatingSystem.IsWindows()) return ExitCodes.Incomplete;
            Console.WriteLine($"Starting Microsoft Defender {action} scan...");
            DefenderCommandResult r = action == "quick" ? await bridge.QuickScanAsync() : await bridge.FullScanAsync();
            if (!string.IsNullOrWhiteSpace(r.StandardOutput)) Console.WriteLine(r.StandardOutput.Trim());
            if (!string.IsNullOrWhiteSpace(r.StandardError)) Console.Error.WriteLine(r.StandardError.Trim());
            Console.WriteLine(r.Success ? "Microsoft Defender scan completed." : $"Microsoft Defender scan failed (exit {r.ExitCode}).");
            return r.Success ? ExitCodes.Success : ExitCodes.Failure;
        }

        if (action == "offline")
        {
            if (!MutationGate.HasConfirmation(args, "REBOOT"))
            {
                Console.Error.WriteLine("Defender Offline reboots the computer. Re-run with: LuckyGuard defender offline --confirm REBOOT");
                return ExitCodes.Usage;
            }
            if (!IsElevated())
            {
                Console.Error.WriteLine("Defender Offline requires an elevated Administrator terminal.");
                return ExitCodes.Incomplete;
            }
            Console.WriteLine("Requesting Microsoft Defender Offline scan. Windows may reboot immediately.");
            DefenderCommandResult r = await bridge.OfflineScanAsync();
            if (!string.IsNullOrWhiteSpace(r.StandardError)) Console.Error.WriteLine(r.StandardError.Trim());
            return r.Success ? ExitCodes.Success : ExitCodes.Failure;
        }

        Console.Error.WriteLine("Usage: LuckyGuard defender <status|quick|full|offline> [--confirm REBOOT]");
        return ExitCodes.Usage;
    }

    private static async Task<int> RunGuardAsync(string[] args)
    {
        string action = args.Length == 0 ? "status" : args[0].ToLowerInvariant();
        if (action == "service") return await RunGuardServiceAsync(args.Skip(1).ToArray());
        if (action is "status" or "roots")
        {
            var defaults = GuardOptions.CreateDefault();
            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            Console.WriteLine("Realtime Guard: READY (foreground + Windows Service / alert-only)");
            Console.WriteLine($"Network poll  : {defaults.NetworkPollInterval.TotalSeconds:0}s");
            Console.WriteLine($"Log           : {GuardJsonlLogger.GetDefaultPath()}");
            Console.WriteLine("Archives      : ZIP/JAR/NUPKG deep scan; RAR/7Z opaque in Phase 8");
            Console.WriteLine("Default roots :");
            foreach (string root in defaults.WatchRoots) Console.WriteLine($"  {root}");
            Console.WriteLine("Auto-remediation: OFF (realtime guard never deletes or quarantines in Phase 8)");
            if (action == "status")
            {
                Console.WriteLine("Run    : LuckyGuard guard run [--watch <path>] [--network-seconds N] [--no-network] [--verbose]");
                Console.WriteLine("Service: LuckyGuard guard service <status|install|start|stop|uninstall>");
            }
            return ExitCodes.Success;
        }

        if (action != "run")
        {
            Console.Error.WriteLine("Usage: LuckyGuard guard <status|roots|run|service> [--watch <path>] [--network-seconds N] [--no-network] [--verbose]");
            return ExitCodes.Usage;
        }
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Realtime Guard is Windows-only.");
            return ExitCodes.Incomplete;
        }

        string[] extraRoots = GetOptions(args, "--watch");
        int networkSeconds = 30;
        string? interval = GetOption(args, "--network-seconds");
        if (interval is not null && (!int.TryParse(interval, out networkSeconds) || networkSeconds < 5 || networkSeconds > 3600))
        {
            Console.Error.WriteLine("--network-seconds must be an integer between 5 and 3600.");
            return ExitCodes.Usage;
        }
        bool noNetwork = args.Any(a => a.Equals("--no-network", StringComparison.OrdinalIgnoreCase));
        bool verbose = args.Any(a => a.Equals("--verbose", StringComparison.OrdinalIgnoreCase));
        GuardOptions options = GuardOptions.CreateDefault(extraRoots, !noNetwork, networkSeconds, verbose);
        if (options.WatchRoots.Count == 0 && !options.MonitorNetwork)
        {
            Console.Error.WriteLine("No valid watch roots and network monitoring is disabled; there is nothing to monitor.");
            return ExitCodes.Usage;
        }

        GuardScanService scanService = GuardScanService.CreateDefault(out string? iocError);
        if (!string.IsNullOrWhiteSpace(iocError))
            Console.Error.WriteLine($"WARNING: verified IOC feed unavailable: {iocError}");

        var logger = new GuardJsonlLogger();
        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cts.Cancel(); };
        Console.CancelKeyPress += handler;
        try
        {
            await using var guard = new RealtimeGuard(options, scanService, async alert =>
            {
                logger.Write(alert);
                PrintGuardAlert(alert);
                await Task.CompletedTask;
            });

            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            Console.WriteLine("Realtime Guard started (ALERT-ONLY). Press Ctrl+C to stop.");
            Console.WriteLine($"Network monitoring: {(options.MonitorNetwork ? $"ON / {options.NetworkPollInterval.TotalSeconds:0}s" : "OFF")}");
            Console.WriteLine($"Log: {logger.Path}");
            Console.WriteLine("Watch roots:");
            foreach (string root in options.WatchRoots) Console.WriteLine($"  {root}");
            Console.WriteLine();

            await guard.RunAsync(cts.Token);
            Console.WriteLine();
            Console.WriteLine("Realtime Guard stopped.");
            Console.WriteLine($"Events={guard.Statistics.EventsObserved}, queued={guard.Statistics.EventsQueued}, debounced={guard.Statistics.EventsDebounced}, fileScans={guard.Statistics.FilesScanned}, networkPolls={guard.Statistics.NetworkPolls}, alerts={guard.Statistics.Alerts}, errors={guard.Statistics.Errors}, overflows={guard.Statistics.WatcherOverflows}, queueDrops={guard.Statistics.QueueDrops}");
            return guard.Statistics.Errors == 0 ? ExitCodes.Success : ExitCodes.Incomplete;
        }
        finally { Console.CancelKeyPress -= handler; }
    }

    private static async Task<int> RunGuardServiceAsync(string[] args)
    {
        string action = args.Length == 0 ? "status" : args[0].ToLowerInvariant();
        var manager = new GuardServiceManager();

        if (action == "status")
        {
            GuardServiceCommandResult query = await manager.QueryAsync();
            Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
            Console.WriteLine(new string('─', 58));
            if (!query.Success && query.Combined.Contains("1060", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Guard Windows Service: NOT INSTALLED");
                Console.WriteLine($"Config : {GuardServiceConfigStore.ConfigPath}");
                Console.WriteLine($"Log    : {GuardServiceConfigStore.LogPath}");
                return ExitCodes.Success;
            }
            Console.WriteLine(query.Combined.Length == 0 ? $"Guard Windows Service query exit={query.ExitCode}" : query.Combined);
            Console.WriteLine($"Config : {GuardServiceConfigStore.ConfigPath}");
            Console.WriteLine($"Log    : {GuardServiceConfigStore.LogPath}");
            return query.Success ? ExitCodes.Success : ExitCodes.Incomplete;
        }

        if (action == "install")
        {
            if (!MutationGate.HasConfirmation(args, "INSTALL"))
            {
                Console.Error.WriteLine("Installing a Windows service changes system persistence. Re-run with: LuckyGuard guard service install --confirm INSTALL");
                return ExitCodes.Usage;
            }
            if (!IsElevated())
            {
                Console.Error.WriteLine("Guard service installation requires an elevated Administrator terminal.");
                return ExitCodes.Incomplete;
            }

            int networkSeconds = 30;
            string? interval = GetOption(args, "--network-seconds");
            if (interval is not null && (!int.TryParse(interval, out networkSeconds) || networkSeconds < 5 || networkSeconds > 3600))
            {
                Console.Error.WriteLine("--network-seconds must be an integer between 5 and 3600.");
                return ExitCodes.Usage;
            }
            bool noNetwork = args.Any(a => a.Equals("--no-network", StringComparison.OrdinalIgnoreCase));
            bool verbose = args.Any(a => a.Equals("--verbose", StringComparison.OrdinalIgnoreCase));
            string[] extraRoots = GetOptions(args, "--watch");
            GuardServiceConfig config = GuardServiceConfigStore.CreateDefault(extraRoots, !noNetwork, networkSeconds, verbose);
            string? serviceExe = GuardServiceManager.LocateServiceExecutable(Directory.GetCurrentDirectory());
            if (serviceExe is null)
            {
                Console.Error.WriteLine("LuckyGuardService.exe was not found. Run scripts\\build.cmd first so the Release service host is built.");
                return ExitCodes.Incomplete;
            }

            GuardServiceCommandResult installed = await manager.InstallAsync(serviceExe, config);
            if (!string.IsNullOrWhiteSpace(installed.Combined)) Console.WriteLine(installed.Combined);
            if (!installed.Success) return ExitCodes.Failure;
            Console.WriteLine("Guard Windows Service installed (alert-only). It is configured for automatic start.");
            Console.WriteLine($"Executable: {GuardServiceManager.InstalledServiceExecutable}");
            Console.WriteLine($"Config    : {GuardServiceConfigStore.ConfigPath}");
            Console.WriteLine($"Log       : {GuardServiceConfigStore.LogPath}");
            Console.WriteLine("Start now : LuckyGuard guard service start");
            return ExitCodes.Success;
        }

        if (action is "start" or "stop")
        {
            if (!IsElevated())
            {
                Console.Error.WriteLine($"Guard service {action} requires an elevated Administrator terminal.");
                return ExitCodes.Incomplete;
            }
            GuardServiceCommandResult result = action == "start" ? await manager.StartAsync() : await manager.StopAsync();
            if (!string.IsNullOrWhiteSpace(result.Combined)) Console.WriteLine(result.Combined);
            return result.Success ? ExitCodes.Success : ExitCodes.Incomplete;
        }

        if (action == "uninstall")
        {
            if (!MutationGate.HasConfirmation(args, "UNINSTALL"))
            {
                Console.Error.WriteLine("Re-run with: LuckyGuard guard service uninstall --confirm UNINSTALL");
                return ExitCodes.Usage;
            }
            if (!IsElevated())
            {
                Console.Error.WriteLine("Guard service uninstall requires an elevated Administrator terminal.");
                return ExitCodes.Incomplete;
            }
            GuardServiceCommandResult result = await manager.UninstallAsync();
            if (!string.IsNullOrWhiteSpace(result.Combined)) Console.WriteLine(result.Combined);
            if (result.Success)
            {
                Console.WriteLine("Guard Windows Service removed. Logs/config were preserved under ProgramData for audit/forensics.");
                return ExitCodes.Success;
            }
            return ExitCodes.Incomplete;
        }

        Console.Error.WriteLine("Usage: LuckyGuard guard service <status|install|start|stop|uninstall>");
        return ExitCodes.Usage;
    }

    private static void PrintGuardAlert(GuardAlert alert)
    {
        Console.WriteLine($"[{alert.ObservedAtUtc:O}] GUARD {alert.Source} {alert.Subject}");
        if (!string.IsNullOrWhiteSpace(alert.Message)) Console.WriteLine($"  {alert.Message}");
        if (alert.Result is null) return;
        Console.WriteLine($"  Verdict={alert.Result.Verdict.ToString().ToUpperInvariant()} Findings={alert.Result.Findings.Count} Errors={alert.Result.Errors.Count}");
        foreach (var finding in alert.Result.Findings)
        {
            Console.WriteLine($"  [{finding.Severity}/{finding.Confidence}] {finding.Id} - {finding.Title}");
            if (!string.IsNullOrWhiteSpace(finding.AffectedPath)) Console.WriteLine($"    Path: {finding.AffectedPath}");
            if (finding.Evidence is not null)
                foreach (var evidence in finding.Evidence.Take(8)) Console.WriteLine($"    {evidence.Kind}: {evidence.Value}");
        }
        foreach (var error in alert.Result.Errors.Take(5)) Console.WriteLine($"  ERROR {error.Scanner}: {error.Message}");
    }

    private static async Task<int> RunScanAsync(string[] args)
    {
        if (!TryParseScanTarget(args, out var target, out string? error))
        {
            Console.Error.WriteLine(error);
            return ExitCodes.Usage;
        }
        return await ExecuteScanAsync(target!, args);
    }

    private static async Task<int> RunVerifyAsync(string[] args)
    {
        if (args.Length == 0) args = ["system"];
        if (!TryParseScanTarget(args, out var target, out string? error))
        {
            Console.Error.WriteLine(error);
            return ExitCodes.Usage;
        }
        ScanResult result = await PerformScanAsync(target!);
        result.Notes.Add("Verification pass: LuckyGuard re-ran the currently loaded detection surfaces after remediation. CLEAN is scoped to those surfaces and IOC feed coverage.");
        return await EmitResultAsync(result, args);
    }

    private static async Task<int> RunCleanAsync(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: LuckyGuard clean <plan|apply|rollback> ...");
            return ExitCodes.Usage;
        }

        switch (args[0].ToLowerInvariant())
        {
            case "plan":
                return await RunCleanPlanAsync(args.Skip(1).ToArray());
            case "apply":
                return await RunCleanApplyAsync(args.Skip(1).ToArray());
            case "rollback":
                return RunCleanRollback(args.Skip(1).ToArray());
            default:
                Console.Error.WriteLine("Usage: LuckyGuard clean <plan|apply|rollback> ...");
                return ExitCodes.Usage;
        }
    }

    private static async Task<int> RunCleanPlanAsync(string[] args)
    {
        if (args.Length == 0) args = ["system"];
        if (!TryParseScanTarget(args, out var target, out string? error))
        {
            Console.Error.WriteLine(error);
            return ExitCodes.Usage;
        }

        ScanResult scan = await PerformScanAsync(target!);
        var plan = new RemediationPlanner().Create(scan);
        string output = GetOption(args, "--output") ?? $"luckyguard-remediation-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json";
        RemediationPlanSerializer.Save(output, plan);

        Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
        Console.WriteLine(new string('─', 58));
        Console.WriteLine($"Source verdict : {scan.Verdict.ToString().ToUpperInvariant()}");
        Console.WriteLine($"Findings       : {scan.Findings.Count}");
        Console.WriteLine($"Plan ID        : {plan.PlanId}");
        Console.WriteLine($"Actions        : {plan.Actions.Count}");
        Console.WriteLine($"Auto-eligible  : {plan.Actions.Count(a => a.AutoEligible)}");
        Console.WriteLine($"Review-only    : {plan.Actions.Count(a => !a.AutoEligible)}");
        Console.WriteLine($"Plan written   : {Path.GetFullPath(output)}");
        foreach (var action in plan.Actions)
            Console.WriteLine($"  [{action.Severity}/{action.Confidence}] {(action.AutoEligible ? "ELIGIBLE" : "REVIEW")} {action.Kind} - {action.Target}");
        Console.WriteLine();
        Console.WriteLine("No system changes were made. Apply requires: LuckyGuard clean apply <plan.json> --confirm APPLY");
        return VerdictResolver.ToExitCode(scan.Verdict);
    }

    private static async Task<int> RunCleanApplyAsync(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("Usage: LuckyGuard clean apply <plan.json> --confirm APPLY");
            return ExitCodes.Usage;
        }
        if (!MutationGate.HasConfirmation(args, "APPLY"))
        {
            Console.Error.WriteLine("Mutation blocked. Re-run with the exact confirmation token: --confirm APPLY");
            return ExitCodes.Usage;
        }

        RemediationPlan plan = RemediationPlanSerializer.Load(args[0]);
        var eligible = plan.Actions.Where(a => a.AutoEligible).ToArray();
        if (eligible.Length == 0)
        {
            Console.WriteLine("Plan contains no auto-eligible remediation actions. No changes were made.");
            return ExitCodes.Success;
        }
        if (eligible.Any(a => a.RequiresElevation) && !IsElevated())
        {
            Console.Error.WriteLine("This remediation plan contains actions requiring an elevated Administrator terminal. No changes were made.");
            return ExitCodes.Incomplete;
        }

        string? validationError = await RevalidatePlanAsync(plan);
        if (validationError is not null)
        {
            Console.Error.WriteLine($"Live revalidation failed: {validationError}");
            Console.Error.WriteLine("No changes were made. Generate a fresh plan from a fresh scan.");
            return ExitCodes.Incomplete;
        }

        var execution = new RemediationExecutor().Apply(plan);
        Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
        Console.WriteLine(new string('─', 58));
        Console.WriteLine($"Plan      : {execution.PlanId}");
        Console.WriteLine($"Execution : {execution.ExecutionId}");
        Console.WriteLine($"Applied   : {execution.Applied.Count}");
        Console.WriteLine($"Skipped   : {execution.Skipped.Count}");
        Console.WriteLine($"Errors    : {execution.Errors.Count}");
        foreach (string applied in execution.Applied) Console.WriteLine($"  APPLIED {applied}");
        foreach (string skipped in execution.Skipped) Console.WriteLine($"  SKIPPED {skipped}");
        foreach (string e in execution.Errors) Console.WriteLine($"  ERROR   {e}");
        Console.WriteLine();
        Console.WriteLine($"Rollback (if required): LuckyGuard clean rollback {execution.ExecutionId} --confirm ROLLBACK");
        Console.WriteLine("Next: LuckyGuard verify system");
        return execution.Success ? ExitCodes.Success : ExitCodes.Failure;
    }

    private static int RunCleanRollback(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("Usage: LuckyGuard clean rollback <execution-id> --confirm ROLLBACK");
            return ExitCodes.Usage;
        }
        if (!MutationGate.HasConfirmation(args, "ROLLBACK"))
        {
            Console.Error.WriteLine("Rollback blocked. Re-run with: --confirm ROLLBACK");
            return ExitCodes.Usage;
        }
        if (OperatingSystem.IsWindows() && !IsElevated())
        {
            Console.Error.WriteLine("Rollback requires an elevated Administrator terminal. No changes were made.");
            return ExitCodes.Incomplete;
        }
        var restored = new RemediationExecutor().Rollback(args[0]);
        Console.WriteLine($"Rollback completed: {restored.Count} item(s) restored.");
        foreach (string item in restored) Console.WriteLine($"  RESTORED {item}");
        return ExitCodes.Success;
    }

    private static int RunQuarantine(string[] args)
    {
        if (args.Length == 0 || args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
        {
            var entries = new QuarantineManager().List();
            Console.WriteLine($"LuckyGuard quarantine: {entries.Count} entr{(entries.Count == 1 ? "y" : "ies")}");
            foreach (var e in entries)
            {
                Console.WriteLine($"  {e.Id}  {e.QuarantinedAtUtc:u}  {e.Severity}/{e.Confidence}");
                Console.WriteLine($"    {e.OriginalPath}");
                Console.WriteLine($"    SHA256 {e.Sha256}");
            }
            return ExitCodes.Success;
        }

        if (args[0].Equals("restore", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length < 2 || !MutationGate.HasConfirmation(args, "RESTORE"))
            {
                Console.Error.WriteLine("Usage: LuckyGuard quarantine restore <id> --confirm RESTORE");
                return ExitCodes.Usage;
            }
            if (OperatingSystem.IsWindows() && !IsElevated())
            {
                Console.Error.WriteLine("Quarantine restore requires an elevated Administrator terminal. No changes were made.");
                return ExitCodes.Incomplete;
            }
            string restored = new QuarantineManager().Restore(args[1]);
            Console.WriteLine($"Restored: {restored}");
            return ExitCodes.Success;
        }

        Console.Error.WriteLine("Usage: LuckyGuard quarantine <list|restore> ...");
        return ExitCodes.Usage;
    }

    private static async Task<string?> RevalidatePlanAsync(RemediationPlan plan)
    {
        ScanResult? persistence = null;
        foreach (var action in plan.Actions.Where(a => a.AutoEligible))
        {
            switch (action.Kind)
            {
                case RemediationActionKind.QuarantineFile:
                {
                    if (!File.Exists(action.Target)) return $"file action target no longer exists: {action.Target}";
                    ScanResult live = await PerformScanAsync(new ScanTarget(ScanTargetKind.File, action.Target));
                    string expected = Path.GetFullPath(action.Target);
                    bool match = live.Findings.Any(f => f.Id.Equals(action.FindingId, StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrWhiteSpace(f.AffectedPath)
                        && Path.GetFullPath(f.AffectedPath).Equals(expected, StringComparison.OrdinalIgnoreCase)
                        && (int)f.Severity >= (int)action.Severity
                        && (int)f.Confidence >= (int)action.Confidence);
                    if (!match) return $"the live file scan no longer reproduces {action.FindingId} for {action.Target}";
                    break;
                }
                case RemediationActionKind.DeleteRegistryValue:
                {
                    persistence ??= await PerformScanAsync(new ScanTarget(ScanTargetKind.System, "persistence"));
                    bool match = persistence.Findings.Any(f => RegistryActionMatchesFinding(action, f));
                    if (!match) return $"the live persistence scan no longer reproduces {action.FindingId} for {action.Target}::{action.ValueName}";
                    break;
                }
                case RemediationActionKind.DeleteScheduledTask:
                case RemediationActionKind.DeleteService:
                {
                    persistence ??= await PerformScanAsync(new ScanTarget(ScanTargetKind.System, "persistence"));
                    bool match = persistence.Findings.Any(f => PersistenceActionMatchesFinding(action, f));
                    if (!match) return $"the live persistence scan no longer reproduces {action.FindingId} for {action.Target}";
                    break;
                }
                case RemediationActionKind.ReviewOnly:
                    break;
                default:
                    return $"action kind {action.Kind} is not supported for automatic remediation";
            }
        }
        return null;
    }

    private static bool RegistryActionMatchesFinding(RemediationAction action, DetectionFinding finding)
    {
        if (!finding.Id.Equals(action.FindingId, StringComparison.OrdinalIgnoreCase)
            || (int)finding.Severity < (int)action.Severity || (int)finding.Confidence < (int)action.Confidence
            || !RegistryLocationParser.TryParseValueLocation(finding.AffectedPath, out var parsed) || parsed is null
            || string.IsNullOrWhiteSpace(action.ValueName) || string.IsNullOrWhiteSpace(action.RegistryView)) return false;
        string actionTarget = action.Target.Replace('/', '\\').Trim();
        string findingTarget = $"{parsed.Hive}\\{parsed.SubKey}";
        return actionTarget.Equals(findingTarget, StringComparison.OrdinalIgnoreCase)
               && action.ValueName.Equals(parsed.ValueName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool PersistenceActionMatchesFinding(RemediationAction action, DetectionFinding finding)
    {
        if (!finding.Id.Equals(action.FindingId, StringComparison.OrdinalIgnoreCase)
            || (int)finding.Severity < (int)action.Severity || (int)finding.Confidence < (int)action.Confidence) return false;
        if (action.Kind == RemediationActionKind.DeleteScheduledTask)
            return string.Equals(finding.AffectedPath, action.Target, StringComparison.OrdinalIgnoreCase);
        if (action.Kind == RemediationActionKind.DeleteService)
        {
            string? service = finding.Evidence?.FirstOrDefault(e => e.Kind.Equals("service", StringComparison.OrdinalIgnoreCase))?.Value;
            return string.Equals(service, action.Target, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private static async Task<int> ExecuteScanAsync(ScanTarget target, string[] args)
    {
        ScanResult result = await PerformScanAsync(target);
        return await EmitResultAsync(result, args);
    }

    private static async Task<ScanResult> PerformScanAsync(ScanTarget target)
    {
        var verified = TryLoadIoc(out _);
        IocStore store = verified?.Store ?? new IocStore();
        string? feedVersion = verified?.Feed.FeedVersion;

        IScanner[] scanners = target.Kind == ScanTargetKind.System
            ? [new SdkScanner(), new ProcessScanner(), new PersistenceScanner(), new NetworkScanner(store, feedVersion)]
            : [new BaselineTargetScanner(), new DeveloperProjectScanner(), new PeScanner(), new SuoScanner(), new ArchiveScanner(store, feedVersion, strictUnsupportedDirectArchive: true), new FileIocScanner(store, feedVersion)];

        var result = await new ScanCoordinator(scanners).ScanAsync(target);
        if (verified is null)
        {
            bool iocRelevant = target.Kind != ScanTargetKind.System || target.Value.Equals("network", StringComparison.OrdinalIgnoreCase) || target.Value.Equals("system", StringComparison.OrdinalIgnoreCase);
            if (iocRelevant) result.Notes.Add("Verified IOC feed could not be loaded. IOC-dependent coverage is incomplete; run 'LuckyGuard ioc verify'.");
        }
        result.Verdict = VerdictResolver.Resolve(result);
        return result;
    }

    private static async Task<int> EmitResultAsync(ScanResult result, string[] args)
    {
        string format = GetOption(args, "--format") ?? "text";
        string? output = GetOption(args, "--output");
        if (!format.Equals("text", StringComparison.OrdinalIgnoreCase) && !format.Equals("json", StringComparison.OrdinalIgnoreCase))
        { Console.Error.WriteLine("--format must be text or json."); return ExitCodes.Usage; }

        string report = format.Equals("json", StringComparison.OrdinalIgnoreCase) ? JsonReportWriter.Write(result) : TextReportWriter.Write(result);
        if (string.IsNullOrWhiteSpace(output)) Console.WriteLine(report);
        else
        {
            string fullOutput = Path.GetFullPath(output);
            Directory.CreateDirectory(Path.GetDirectoryName(fullOutput) ?? Directory.GetCurrentDirectory());
            await File.WriteAllTextAsync(fullOutput, report);
            Console.WriteLine($"Report written: {fullOutput}");
        }
        return VerdictResolver.ToExitCode(result.Verdict);
    }

    private static bool TryParseScanTarget(string[] args, out ScanTarget? target, out string? error)
    {
        target = null;
        error = null;
        if (args.Length >= 1 && IsSystemScan(args[0]))
        {
            target = new ScanTarget(ScanTargetKind.System, args[0].ToLowerInvariant());
            return true;
        }
        if (args.Length < 2)
        {
            error = "Usage: LuckyGuard <scan|verify> <path|solution|project|file|archive> <target> [--format text|json] [--output file]\n       LuckyGuard <scan|verify> <sdk|processes|persistence|network|system>";
            return false;
        }
        if (args[0].Equals("archive", StringComparison.OrdinalIgnoreCase))
        {
            string ext = Path.GetExtension(args[1]);
            if (!new[] { ".zip", ".jar", ".nupkg", ".rar", ".7z" }.Contains(ext, StringComparer.OrdinalIgnoreCase))
            {
                error = "Archive target must use .zip, .jar, .nupkg, .rar, or .7z. ZIP/JAR/NUPKG receive deep inspection; RAR/7Z report partial coverage.";
                return false;
            }
        }

        ScanTargetKind? kind = args[0].ToLowerInvariant() switch
        {
            "path" => ScanTargetKind.Path,
            "solution" => ScanTargetKind.Solution,
            "project" => ScanTargetKind.Project,
            "file" => ScanTargetKind.File,
            "archive" => ScanTargetKind.File,
            _ => null
        };
        if (kind is null) { error = $"Unknown scan target type: {args[0]}"; return false; }
        target = new ScanTarget(kind.Value, args[1]);
        return true;
    }

    private static VerifiedIocFeed? TryLoadIoc(out string? error)
    {
        error = null;
        try
        {
            var paths = IocFeedLoader.LocateDefault();
            if (paths is null) { error = "IOC feed files were not found."; return null; }
            return IocFeedLoader.LoadVerified(paths.Value.Feed, paths.Value.Signature, paths.Value.PublicKey);
        }
        catch (Exception ex) { error = ex.Message; return null; }
    }

    private static async Task<int> RunInteractiveShellAsync()
    {
        Console.Clear();
        PrintTerminalBanner();
        await PrintQuickDashboardAsync();
        Console.WriteLine();
        WriteAccent("Type 'help' for commands, 'scan system' for a full scan, or 'exit' to close.");
        Console.WriteLine();

        while (true)
        {
            WritePrompt();
            string? line = Console.ReadLine();
            if (line is null) return ExitCodes.Success;
            line = line.Trim();
            if (line.Length == 0) continue;
            if (line.Equals("exit", StringComparison.OrdinalIgnoreCase)
                || line.Equals("quit", StringComparison.OrdinalIgnoreCase)
                || line.Equals("q", StringComparison.OrdinalIgnoreCase))
                return ExitCodes.Success;
            if (line.Equals("clear", StringComparison.OrdinalIgnoreCase)
                || line.Equals("cls", StringComparison.OrdinalIgnoreCase))
            {
                Console.Clear();
                PrintTerminalBanner();
                continue;
            }

            string[] commandArgs;
            try { commandArgs = SplitInteractiveCommandLine(line); }
            catch (FormatException ex)
            {
                WriteError($"Input error: {ex.Message}");
                continue;
            }

            Console.WriteLine();
            _ = await Main(commandArgs);
            Console.WriteLine();
        }
    }

    private static async Task PrintQuickDashboardAsync()
    {
        var feed = TryLoadIoc(out _);
        WriteStatusLine("IOC feed", feed is null ? "NOT VERIFIED" : $"VERIFIED / {feed.Store.Count} entries", feed is not null);

        try
        {
            DefenderStatus defender = await new DefenderBridge().GetStatusAsync();
            bool defenderHealthy = defender.Available && defender.AntivirusEnabled && defender.RealTimeProtectionEnabled;
            WriteStatusLine("Defender", defenderHealthy ? "ON / realtime active" : defender.Available ? "ATTENTION" : "UNAVAILABLE", defenderHealthy);
        }
        catch { WriteStatusLine("Defender", "status unavailable", false); }

        try
        {
            GuardServiceCommandResult service = await new GuardServiceManager().QueryAsync();
            string combined = service.Combined;
            bool running = service.Success && combined.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
            string label = running ? "RUNNING" : service.Success ? "INSTALLED / stopped" : "not installed";
            WriteStatusLine("Realtime service", label, running);
        }
        catch { WriteStatusLine("Realtime service", "status unavailable", false); }

        Console.WriteLine();
        Console.WriteLine("  Common commands");
        Console.WriteLine("  ─────────────────────────────────────────────────────");
        Console.WriteLine("  scan system        Full LuckyWare-focused system scan");
        Console.WriteLine("  guard status       Realtime protection status");
        Console.WriteLine("  defender status    Microsoft Defender status");
        Console.WriteLine("  quarantine list    Isolated files");
        Console.WriteLine("  verify system      Re-run all loaded detection surfaces");
        Console.WriteLine("  update check       Check official GitHub stable release");
    }

    internal static string[] SplitInteractiveCommandLine(string commandLine)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;
        char quote = '\0';
        for (int i = 0; i < commandLine.Length; i++)
        {
            char c = commandLine[i];
            if (inQuotes)
            {
                if (c == quote) { inQuotes = false; quote = '\0'; continue; }
                if (c == '\\' && i + 1 < commandLine.Length && commandLine[i + 1] == quote)
                { current.Append(quote); i++; continue; }
                current.Append(c);
                continue;
            }
            if (c is '"' or '\'') { inQuotes = true; quote = c; continue; }
            if (char.IsWhiteSpace(c))
            {
                if (current.Length > 0) { result.Add(current.ToString()); current.Clear(); }
                continue;
            }
            current.Append(c);
        }
        if (inQuotes) throw new FormatException("Unterminated quoted argument.");
        if (current.Length > 0) result.Add(current.ToString());
        return result.ToArray();
    }

    private static void PrintTerminalBanner()
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  ██╗     ██╗   ██╗ ██████╗██╗  ██╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ");
        Console.WriteLine("  ██║     ██║   ██║██╔════╝██║ ██╔╝╚██╗ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗");
        Console.WriteLine("  ██║     ██║   ██║██║     █████╔╝  ╚████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║");
        Console.WriteLine("  ██║     ██║   ██║██║     ██╔═██╗   ╚██╔╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║");
        Console.WriteLine("  ███████╗╚██████╔╝╚██████╗██║  ██╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝");
        Console.WriteLine("  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  LuckyWare Protection Toolkit  •  {BuildInfo.Version}");
        Console.ForegroundColor = previous;
        Console.WriteLine();
    }

    private static void WriteStatusLine(string name, string value, bool healthy)
    {
        Console.Write($"  {name,-18} ");
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = healthy ? ConsoleColor.Green : ConsoleColor.Yellow;
        Console.WriteLine(value);
        Console.ForegroundColor = previous;
    }

    private static void WritePrompt()
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.Write("luckyguard");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write(" > ");
        Console.ForegroundColor = previous;
    }

    private static void WriteAccent(string text)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(text);
        Console.ForegroundColor = previous;
    }

    private static void WriteError(string text)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine(text);
        Console.ForegroundColor = previous;
    }

    private static void PrintStatus()
    {
        var feed = TryLoadIoc(out _);
        Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
        Console.WriteLine(new string('─', 58));
        Console.WriteLine($"Runtime : {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS      : {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
        Console.WriteLine($"Arch    : {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
        Console.WriteLine("Mode    : 1.0 RC / public distribution + scanner/cleaner + Defender + realtime guard/service + archive scanner");
        Console.WriteLine("Mutation: GATED (clean apply / rollback / quarantine restore require explicit confirmation tokens)");
        Console.WriteLine("Loaded  : developer, PE/SUO/SDK, archive, process, persistence, network/C2, signed IOC/update, quarantine, remediation, Defender bridge, realtime guard + Windows Service host");
        Console.WriteLine($"IOC feed: {(feed is null ? "NOT VERIFIED" : $"VERIFIED ({feed.Feed.FeedVersion}, {feed.Store.Count} entries)")}");
        Console.WriteLine("Pending : trusted signing identity + configured GitHub repository before stable 1.0.0; broader WMI/AppInit auto-cleanup remains intentionally conservative");
    }

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool IsSystemScan(string value) => value.Equals("sdk", StringComparison.OrdinalIgnoreCase)
        || value.Equals("processes", StringComparison.OrdinalIgnoreCase)
        || value.Equals("persistence", StringComparison.OrdinalIgnoreCase)
        || value.Equals("network", StringComparison.OrdinalIgnoreCase)
        || value.Equals("system", StringComparison.OrdinalIgnoreCase);

    private static string[] GetOptions(string[] args, string name)
    {
        var values = new List<string>();
        for (int i = 0; i < args.Length - 1; i++) if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase)) values.Add(args[i + 1]);
        return values.ToArray();
    }

    private static string? GetOption(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++) if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static bool IsHelp(string arg) => arg is "-h" or "--help" or "help" or "/?";

    private static void PrintHelp()
    {
        Console.WriteLine($"LuckyGuard {BuildInfo.Version}");
        Console.WriteLine("LuckyWare Protection & Remediation Toolkit");
        Console.WriteLine("  LuckyGuard                 Open interactive terminal dashboard");
        Console.WriteLine();
        Console.WriteLine("Scanning:");
        Console.WriteLine("  LuckyGuard scan <path|solution|project|file|archive> <target> [--format text|json] [--output file]");
        Console.WriteLine("  LuckyGuard scan <sdk|processes|persistence|network|system>");
        Console.WriteLine("  LuckyGuard verify [system|network|persistence|...]");
        Console.WriteLine();
        Console.WriteLine("Remediation:");
        Console.WriteLine("  LuckyGuard clean plan system [--output remediation.json]");
        Console.WriteLine("  LuckyGuard clean plan file <path> [--output remediation.json]");
        Console.WriteLine("  LuckyGuard clean apply <remediation.json> --confirm APPLY");
        Console.WriteLine("  LuckyGuard clean rollback <execution-id> --confirm ROLLBACK");
        Console.WriteLine("  LuckyGuard quarantine list");
        Console.WriteLine("  LuckyGuard quarantine restore <id> --confirm RESTORE");
        Console.WriteLine();
        Console.WriteLine("IOC:");
        Console.WriteLine("  LuckyGuard ioc status");
        Console.WriteLine("  LuckyGuard ioc verify");
        Console.WriteLine("  LuckyGuard ioc update");
        Console.WriteLine("  LuckyGuard ioc update --feed-url <https-url> --signature-url <https-url>");
        Console.WriteLine();
        Console.WriteLine("Realtime Guard:");
        Console.WriteLine("  LuckyGuard guard status");
        Console.WriteLine("  LuckyGuard guard roots");
        Console.WriteLine("  LuckyGuard guard run [--watch <path>] [--network-seconds N] [--no-network] [--verbose]");
        Console.WriteLine("  LuckyGuard guard service status");
        Console.WriteLine("  LuckyGuard guard service install --confirm INSTALL [--watch <path>] [--network-seconds N] [--no-network]");
        Console.WriteLine("  LuckyGuard guard service start");
        Console.WriteLine("  LuckyGuard guard service stop");
        Console.WriteLine("  LuckyGuard guard service uninstall --confirm UNINSTALL");
        Console.WriteLine();
        Console.WriteLine("Application updates:");
        Console.WriteLine("  LuckyGuard update check");
        Console.WriteLine();
        Console.WriteLine("Microsoft Defender:");
        Console.WriteLine("  LuckyGuard defender status");
        Console.WriteLine("  LuckyGuard defender quick");
        Console.WriteLine("  LuckyGuard defender full");
        Console.WriteLine("  LuckyGuard defender offline --confirm REBOOT");
        Console.WriteLine();
        Console.WriteLine("Safety: scan/guard are read-only. Realtime Guard and its Windows Service are alert-only in 1.0 RC. Cleaner mutations still require explicit confirmation and live revalidation.");
    }
}
