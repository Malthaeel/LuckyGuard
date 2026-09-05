using System.Text.Json;
using System.Text.Json.Serialization;
using LuckyGuard.Quarantine;
using LuckyGuard.Core.Detection;
using LuckyGuard.Remediation.Models;

namespace LuckyGuard.Remediation.Execution;

public sealed class RemediationExecutor
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly QuarantineManager _quarantine;
    private readonly string _journalRoot;

    public RemediationExecutor(QuarantineManager? quarantine = null, string? journalRoot = null)
    {
        _quarantine = quarantine ?? new QuarantineManager();
        _journalRoot = Path.GetFullPath(journalRoot ?? GetDefaultJournalRoot());
    }

    public RemediationExecutionResult Apply(RemediationPlan plan)
    {
        if (plan.SchemaVersion != 1) throw new InvalidDataException("Unsupported remediation plan schema.");
        if (plan.SourceVerdict is Verdict.Incomplete or Verdict.Failed or Verdict.NotAssessed)
            throw new InvalidOperationException($"Refusing remediation from source verdict {plan.SourceVerdict}.");
        Directory.CreateDirectory(_journalRoot);
        string executionId = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
        var journal = new RemediationJournal
        {
            ExecutionId = executionId,
            PlanId = plan.PlanId,
            CreatedAtUtc = DateTimeOffset.UtcNow
        };
        var result = new RemediationExecutionResult { PlanId = plan.PlanId, ExecutionId = executionId };
        var seenMutations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string executionDir = Path.Combine(_journalRoot, executionId);
        Directory.CreateDirectory(executionDir);
        PersistJournal(executionDir, journal);

        foreach (var action in plan.Actions)
        {
            if (!action.AutoEligible || action.Kind == RemediationActionKind.ReviewOnly)
            {
                result.Skipped.Add($"{action.Id}: {action.Title} (review-only)");
                continue;
            }

            string mutationKey = $"{action.Kind}|{action.Target}|{action.ValueName}|{action.RegistryView}";
            if (!seenMutations.Add(mutationKey))
            {
                result.Skipped.Add($"{action.Id}: {action.Title} (duplicate mutation target)");
                continue;
            }

            try
            {
                switch (action.Kind)
                {
                    case RemediationActionKind.QuarantineFile:
                    {
                        var entry = _quarantine.QuarantineFile(action.Target, [action.FindingId], action.Severity, action.Confidence);
                        journal.QuarantineEntryIds.Add(entry.Id);
                        break;
                    }
                    case RemediationActionKind.DeleteRegistryValue:
                    {
                        if (string.IsNullOrWhiteSpace(action.ValueName) || string.IsNullOrWhiteSpace(action.RegistryView))
                            throw new InvalidDataException("Registry remediation action is missing value name or registry view.");
                        journal.RegistryBackups.Add(RegistryRemediator.DeleteValueWithBackup(action.Target, action.ValueName, action.RegistryView));
                        break;
                    }
                    case RemediationActionKind.DeleteScheduledTask:
                    {
                        journal.ScheduledTaskBackups.Add(ScheduledTaskRemediator.DeleteWithBackup(action.Target, executionDir));
                        break;
                    }
                    case RemediationActionKind.DeleteService:
                    {
                        journal.ServiceBackups.Add(ServiceRemediator.DeleteWithBackup(action.Target, executionDir));
                        break;
                    }
                    default:
                        result.Skipped.Add($"{action.Id}: {action.Title} (unsupported remediation action)");
                        continue;
                }
                journal.AppliedActionIds.Add(action.Id);
                PersistJournal(executionDir, journal);
                result.Applied.Add($"{action.Id}: {action.Title}");
            }
            catch (Exception ex)
            {
                result.Errors.Add($"{action.Id}: {action.Title}: {ex.Message}");
            }
        }

        result.FinishedAtUtc = DateTimeOffset.UtcNow;
        PersistJournal(executionDir, journal);
        return result;
    }

    public IReadOnlyList<string> Rollback(string executionId)
    {
        string journalPath = SafeJournalPath(executionId);
        var journal = JsonSerializer.Deserialize<RemediationJournal>(File.ReadAllText(journalPath), JsonOptions)
                      ?? throw new InvalidDataException("Remediation journal is invalid.");
        string executionDir = Path.GetDirectoryName(journalPath) ?? throw new InvalidDataException("Remediation journal path is invalid.");
        var restored = new List<string>();

        // Restore deleted services/tasks first, then registry values and quarantined files.
        // Every restorer refuses overwrite conflicts.
        foreach (var backup in journal.ServiceBackups.AsEnumerable().Reverse())
        {
            EnsureBackupInsideExecution(backup.RegistryBackupFile, executionDir, "service-", ".reg");
            ServiceRemediator.Restore(backup);
            restored.Add($"service:{backup.ServiceName} (SCM refresh/reboot may be required)");
        }

        foreach (var backup in journal.ScheduledTaskBackups.AsEnumerable().Reverse())
        {
            EnsureBackupInsideExecution(backup.XmlBackupFile, executionDir, "task-", ".xml");
            ScheduledTaskRemediator.Restore(backup);
            restored.Add($"task:{backup.TaskPath}");
        }

        foreach (var backup in journal.RegistryBackups.AsEnumerable().Reverse())
        {
            RegistryRemediator.Restore(backup);
            restored.Add($"registry:{backup.Hive}\\{backup.SubKey}::{backup.ValueName} [{backup.View}]");
        }

        foreach (string quarantineId in journal.QuarantineEntryIds.AsEnumerable().Reverse())
        {
            string path = _quarantine.Restore(quarantineId);
            restored.Add($"file:{path}");
        }
        return restored;
    }

    private static void EnsureBackupInsideExecution(string backupPath, string executionDir, string prefix, string extension)
    {
        string root = Path.GetFullPath(executionDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string full = Path.GetFullPath(backupPath);
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Rollback backup path escapes the LuckyGuard execution directory.");
        string name = Path.GetFileName(full);
        if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !name.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rollback backup filename does not match LuckyGuard's expected format.");
    }

    private static void PersistJournal(string executionDir, RemediationJournal journal)
    {
        string path = Path.Combine(executionDir, "journal.json");
        string temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(journal, JsonOptions));
        File.Move(temp, path, overwrite: true);
    }

    private string SafeJournalPath(string executionId)
    {
        if (string.IsNullOrWhiteSpace(executionId) || executionId.Contains("..", StringComparison.Ordinal) || executionId.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("Invalid execution id.", nameof(executionId));
        string path = Path.Combine(_journalRoot, executionId, "journal.json");
        if (!File.Exists(path)) throw new FileNotFoundException("Remediation journal was not found.", path);
        return path;
    }

    private static string GetDefaultJournalRoot()
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(programData)) programData = Path.GetTempPath();
        return Path.Combine(programData, "LuckyGuard", "Remediation");
    }
}
