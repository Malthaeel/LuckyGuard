using System.Diagnostics;
using System.Text.Json;

namespace LuckyGuard.Defender;

public sealed class DefenderBridge
{
    public async Task<DefenderStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) return new DefenderStatus { Error = "Microsoft Defender integration is Windows-only." };
        const string cmd = "$ErrorActionPreference='Stop'; Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntispywareEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress";
        DefenderCommandResult r = await RunPowerShellAsync(cmd, cancellationToken);
        if (!r.Success) return new DefenderStatus { Error = string.IsNullOrWhiteSpace(r.StandardError) ? $"PowerShell exited {r.ExitCode}." : r.StandardError.Trim() };
        try { return ParseStatusJson(r.StandardOutput); }
        catch (Exception ex) { return new DefenderStatus { Error = $"Could not parse Defender status: {ex.Message}" }; }
    }

    internal static DefenderStatus ParseStatusJson(string json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        DateTimeOffset? updated = null;
        if (root.TryGetProperty("AntivirusSignatureLastUpdated", out var u) && u.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(u.GetString(), out var dto)) updated = dto;
        return new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = GetBool(root, "AntivirusEnabled"),
            RealTimeProtectionEnabled = GetBool(root, "RealTimeProtectionEnabled"),
            BehaviorMonitorEnabled = GetBool(root, "BehaviorMonitorEnabled"),
            IoavProtectionEnabled = GetBool(root, "IoavProtectionEnabled"),
            AntispywareEnabled = GetBool(root, "AntispywareEnabled"),
            AntivirusSignatureVersion = root.TryGetProperty("AntivirusSignatureVersion", out var v) ? v.GetString() : null,
            AntivirusSignatureLastUpdated = updated
        };
    }

    public Task<DefenderCommandResult> QuickScanAsync(CancellationToken cancellationToken = default) =>
        RunPowerShellAsync("$ErrorActionPreference='Stop'; Start-MpScan -ScanType QuickScan", cancellationToken);

    public Task<DefenderCommandResult> FullScanAsync(CancellationToken cancellationToken = default) =>
        RunPowerShellAsync("$ErrorActionPreference='Stop'; Start-MpScan -ScanType FullScan", cancellationToken);

    public Task<DefenderCommandResult> OfflineScanAsync(CancellationToken cancellationToken = default) =>
        RunPowerShellAsync("$ErrorActionPreference='Stop'; Start-MpWDOScan", cancellationToken);

    internal static async Task<DefenderCommandResult> RunPowerShellAsync(string command, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(command);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start Windows PowerShell.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return new DefenderCommandResult(process.ExitCode, await stdout, await stderr);
    }

    private static bool GetBool(JsonElement root, string name) => root.TryGetProperty(name, out var v) && (v.ValueKind is JsonValueKind.True or JsonValueKind.False) && v.GetBoolean();
}
