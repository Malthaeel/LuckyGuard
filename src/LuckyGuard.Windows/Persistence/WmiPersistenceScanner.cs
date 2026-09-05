using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Windows.Persistence;

internal static class WmiPersistenceScanner
{
    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        if (!OperatingSystem.IsWindows()) return;
        int commandConsumers = 0, scriptConsumers = 0, bindings = 0;
        try
        {
            Type? type = Type.GetTypeFromProgID("WbemScripting.SWbemLocator");
            if (type is null) return;
            dynamic locator = Activator.CreateInstance(type)!;
            dynamic services = locator.ConnectServer(".", @"root\subscription");

            foreach (dynamic consumer in services.ExecQuery("SELECT * FROM CommandLineEventConsumer"))
            {
                commandConsumers++;
                string name = Safe(() => consumer.Name) ?? "<unnamed>";
                string command = $"{Safe(() => consumer.ExecutablePath)} {Safe(() => consumer.CommandLineTemplate)}".Trim();
                var finding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.WMI_COMMAND_CONSUMER", "Suspicious WMI command-line event consumer", $"WMI:CommandLineEventConsumer:{name}", command);
                if (finding is not null) result.Findings.Add(finding);
            }
            foreach (dynamic consumer in services.ExecQuery("SELECT * FROM ActiveScriptEventConsumer"))
            {
                scriptConsumers++;
                string name = Safe(() => consumer.Name) ?? "<unnamed>";
                string script = Safe(() => consumer.ScriptText) ?? string.Empty;
                var finding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.WMI_SCRIPT_CONSUMER", "Suspicious WMI active-script event consumer", $"WMI:ActiveScriptEventConsumer:{name}", script);
                if (finding is not null) result.Findings.Add(finding);
            }
            foreach (dynamic _ in services.ExecQuery("SELECT * FROM __FilterToConsumerBinding")) bindings++;
        }
        catch (Exception ex)
        {
            result.Errors.Add(new ScanError("WmiPersistenceScanner", ex.Message, @"root\subscription"));
            result.Notes.Add("WMI permanent-event subscription coverage is incomplete. Re-run from an elevated terminal if access is denied.");
        }
        result.Metrics["wmiCommandConsumersInspected"] = commandConsumers;
        result.Metrics["wmiScriptConsumersInspected"] = scriptConsumers;
        result.Metrics["wmiBindingsInspected"] = bindings;
    }

    private static string? Safe(Func<object?> getter) { try { return getter()?.ToString(); } catch { return null; } }
}
