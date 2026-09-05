using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Windows.Persistence;

internal static class ScheduledTaskPersistenceScanner
{
    public static void Scan(ScanResult result, bool ignoreInaccessible)
    {
        if (!OperatingSystem.IsWindows()) return;
        int tasks = 0, execActions = 0;
        try
        {
            Type? type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return;
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();
            dynamic root = service.GetFolder("\\");
            ScanFolder(root, result, ref tasks, ref execActions);
        }
        catch (Exception ex)
        {
            result.Errors.Add(new ScanError("ScheduledTaskPersistenceScanner", ex.Message, "Task Scheduler"));
            result.Notes.Add("Scheduled Task coverage is incomplete. Re-run from an elevated terminal if access is denied.");
        }
        result.Metrics["scheduledTasksInspected"] = tasks;
        result.Metrics["scheduledTaskExecActionsInspected"] = execActions;
    }

    private static void ScanFolder(dynamic folder, ScanResult result, ref int tasks, ref int execActions)
    {
        foreach (dynamic task in folder.GetTasks(1))
        {
            tasks++;
            string taskPath = SafeString(() => task.Path) ?? "<unknown task>";
            dynamic definition = task.Definition;
            foreach (dynamic action in definition.Actions)
            {
                int type = SafeInt(() => action.Type);
                if (type != 0) continue; // TASK_ACTION_EXEC
                execActions++;
                string command = $"{SafeString(() => action.Path)} {SafeString(() => action.Arguments)}".Trim();
                var finding = PersistenceFindingFactory.FromCommand("LG.PERSISTENCE.TASK_COMMAND", "Suspicious Scheduled Task command", taskPath, command);
                if (finding is not null) result.Findings.Add(finding);
            }
        }

        foreach (dynamic child in folder.GetFolders(0)) ScanFolder(child, result, ref tasks, ref execActions);
    }

    private static string? SafeString(Func<object?> getter) { try { return getter()?.ToString(); } catch { return null; } }
    private static int SafeInt(Func<object?> getter) { try { return Convert.ToInt32(getter()); } catch { return -1; } }
}
