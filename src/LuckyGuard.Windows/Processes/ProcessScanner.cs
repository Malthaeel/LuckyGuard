using System.ComponentModel;
using System.Diagnostics;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Windows.Native;
using LuckyGuard.Windows.Security;

namespace LuckyGuard.Windows.Processes;

public sealed class ProcessScanner : IScanner
{
    public string Name => "ProcessScanner";
    public bool CanScan(ScanTarget target) => target.Kind == ScanTargetKind.System && (target.Value.Equals("processes", StringComparison.OrdinalIgnoreCase) || target.Value.Equals("system", StringComparison.OrdinalIgnoreCase));

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        if (!OperatingSystem.IsWindows())
        {
            result.Notes.Add("Process scanner is Windows-only.");
            return Task.CompletedTask;
        }

        var parentMap = ProcessNative.GetParentMap();
        int enumerated = 0, commandLines = 0, paths = 0, trusted = 0, skipped = 0;
        foreach (var process in Process.GetProcesses())
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            using (process)
            {
                try
                {
                    int pid = process.Id;
                    enumerated++;
                    string name = process.ProcessName;
                    string? path = ProcessNative.QueryImagePath(pid);
                    if (path is not null) paths++;
                    string? command = ProcessNative.QueryCommandLine(pid);
                    if (command is not null) commandLines++;
                    bool? trustedSignature = path is not null ? AuthenticodeTrust.IsTrusted(path) : null;
                    if (trustedSignature == true) trusted++;
                    int parent = parentMap.GetValueOrDefault(pid, 0);
                    result.Findings.AddRange(ProcessAnalyzer.Analyze(new ProcessSnapshot(pid, parent, name, path, command, trustedSignature)));
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
                {
                    skipped++;
                    if (!context.Options.IgnoreInaccessible) result.Errors.Add(new ScanError(Name, ex.Message));
                }
            }
        }

        result.Metrics["processesEnumerated"] = enumerated;
        result.Metrics["processesSkipped"] = skipped;
        result.Metrics["processPathsResolved"] = paths;
        result.Metrics["processCommandLinesResolved"] = commandLines;
        result.Metrics["processTrustedSignatures"] = trusted;
        result.Notes.Add("Process inspection is read-only. Microsoft-signed process names are never treated as malicious by name alone; path and command context are correlated.");
        if (result.Findings.Count == 0 && result.Errors.Count == 0) result.Verdict = Verdict.Clean;
        return Task.CompletedTask;
    }
}
