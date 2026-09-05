using LuckyGuard.Core.Scanning;
using LuckyGuard.Core.Detection;
using Microsoft.Win32;

namespace LuckyGuard.Windows.Persistence;

internal static class ServicePersistenceScanner
{
    private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";

    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        int services = 0;
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(ServicesPath, false);
            if (servicesKey is null) return;
            foreach (string serviceName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var key = servicesKey.OpenSubKey(serviceName, false);
                    if (key is null) continue;
                    string? imagePath = key.GetValue("ImagePath")?.ToString();
                    if (string.IsNullOrWhiteSpace(imagePath)) continue;
                    services++;
                    string location = $"HKLM\\{ServicesPath}\\{serviceName}";
                    var commandFinding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.SERVICE_COMMAND", "Suspicious service command", location, imagePath,
                        extraEvidence: [new Evidence("service", serviceName)]);
                    if (commandFinding is not null) { result.Findings.Add(commandFinding); continue; }

                    string candidate = ServiceImageAnalyzer.NormalizeImagePath(imagePath);
                    int startType = Convert.ToInt32(key.GetValue("Start", 3));
                    bool imageExists = File.Exists(candidate);
                    var serviceFinding = ServiceImageAnalyzer.Analyze(serviceName, imagePath, startType, imageExists, location);
                    if (serviceFinding is not null) result.Findings.Add(serviceFinding);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
                {
                    if (!ignoreInaccessible) result.Errors.Add(new ScanError("ServicePersistenceScanner", ex.Message, serviceName));
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            if (!ignoreInaccessible) result.Errors.Add(new ScanError("ServicePersistenceScanner", ex.Message, ServicesPath));
        }
        result.Metrics["servicesInspected"] = services;
    }

}
