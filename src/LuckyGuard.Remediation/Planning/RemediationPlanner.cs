using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Remediation.Models;

namespace LuckyGuard.Remediation.Planning;

public sealed class RemediationPlanner
{
    private static readonly HashSet<string> FileQuarantineIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "LW.IOC.SHA256_MATCH",
        "LW.PE.ENTRYPOINT_RCD"
    };

    private static readonly HashSet<string> RegistryValueIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "LG.PERSISTENCE.RUN_COMMAND",
        "LG.PERSISTENCE.IFEO_COMMAND"
    };

    private static readonly HashSet<string> TaskIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "LG.PERSISTENCE.TASK_COMMAND"
    };

    private static readonly HashSet<string> ServiceIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "LG.PERSISTENCE.SERVICE_COMMAND"
    };

    public RemediationPlan Create(ScanResult scan)
    {
        var plan = new RemediationPlan
        {
            PlanId = Guid.NewGuid().ToString("N"),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            SourceTarget = scan.Target,
            SourceVerdict = scan.Verdict,
            SourceFindings = scan.Findings.Count
        };

        var quarantinedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (DetectionFinding finding in scan.Findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Confidence))
        {
            if (TryPlanFileQuarantine(finding, quarantinedPaths, out var fileAction))
            {
                if (fileAction is not null) plan.Actions.Add(fileAction);
                continue;
            }

            if (TryPlanRegistryValue(finding, out var registryAction))
            {
                plan.Actions.Add(registryAction!);
                continue;
            }

            if (TryPlanScheduledTask(finding, out var taskAction))
            {
                plan.Actions.Add(taskAction!);
                continue;
            }

            if (TryPlanService(finding, out var serviceAction))
            {
                plan.Actions.Add(serviceAction!);
                continue;
            }

            plan.Actions.Add(CreateReviewAction(finding));
        }

        if (plan.Actions.Count == 0) plan.Notes.Add("No remediation actions were generated because the scan contained no findings.");
        if (plan.Actions.Any(a => !a.AutoEligible)) plan.Notes.Add("Review-only actions are never executed by 'clean apply'. They require manual investigation or a later LuckyGuard remediation module.");
        plan.Notes.Add("Mutation is gated: generating a plan changes nothing. 'clean apply <plan> --confirm APPLY' is required for eligible actions.");
        return plan;
    }

    private static bool TryPlanFileQuarantine(DetectionFinding finding, HashSet<string> seen, out RemediationAction? action)
    {
        action = null;
        if (!FileQuarantineIds.Contains(finding.Id) || string.IsNullOrWhiteSpace(finding.AffectedPath)) return false;
        string full;
        try { full = Path.GetFullPath(finding.AffectedPath); }
        catch { return false; }
        if (!File.Exists(full)) return false;
        if (!seen.Add(full)) return true; // duplicate evidence for the same payload; first action owns it.

        bool exactHash = finding.Id.Equals("LW.IOC.SHA256_MATCH", StringComparison.OrdinalIgnoreCase);
        bool strongPe = finding.Id.Equals("LW.PE.ENTRYPOINT_RCD", StringComparison.OrdinalIgnoreCase)
                        && finding.Severity == DetectionSeverity.Critical;
        bool eligible = exactHash && (int)finding.Severity >= (int)DetectionSeverity.High && (int)finding.Confidence >= (int)DetectionConfidence.Community
                        || strongPe && (int)finding.Confidence >= (int)DetectionConfidence.Community;

        action = new RemediationAction
        {
            Id = Guid.NewGuid().ToString("N"),
            Kind = RemediationActionKind.QuarantineFile,
            FindingId = finding.Id,
            Title = $"Quarantine {Path.GetFileName(full)}",
            Severity = finding.Severity,
            Confidence = finding.Confidence,
            Target = full,
            AutoEligible = eligible,
            RequiresElevation = true,
            Reason = exactHash
                ? "Exact SHA-256 IOC matches are strong file evidence; the file can be isolated without deleting the quarantine copy."
                : "The PE entry point is inside a LuckyWare-style .rcd section; isolate the binary instead of patching it in place."
        };
        return true;
    }

    private static bool TryPlanRegistryValue(DetectionFinding finding, out RemediationAction? action)
    {
        action = null;
        if (!RegistryValueIds.Contains(finding.Id)) return false;
        if (!RegistryLocationParser.TryParseValueLocation(finding.AffectedPath, out var location) || location is null) return false;
        string? registryView = finding.Evidence?.FirstOrDefault(e => e.Kind.Equals("registryView", StringComparison.OrdinalIgnoreCase))?.Value;
        if (registryView is not ("Registry64" or "Registry32")) return false;

        // Persistence deletion is intentionally stricter than detection. Heuristic/community
        // findings remain review-only even when HIGH.
        bool eligible = finding.Confidence is DetectionConfidence.Confirmed or DetectionConfidence.Reversed
                        && (int)finding.Severity >= (int)DetectionSeverity.High;

        if (!eligible) return false;
        action = new RemediationAction
        {
            Id = Guid.NewGuid().ToString("N"),
            Kind = RemediationActionKind.DeleteRegistryValue,
            FindingId = finding.Id,
            Title = $"Remove persistence registry value {location.ValueName}",
            Severity = finding.Severity,
            Confidence = finding.Confidence,
            Target = $"{location.Hive}\\{location.SubKey}",
            ValueName = location.ValueName,
            RegistryView = registryView,
            AutoEligible = true,
            RequiresElevation = location.Hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase),
            Reason = "Only HIGH/CRITICAL persistence with Reversed/Confirmed confidence is eligible for automatic registry-value removal. Original value data is journaled before deletion."
        };
        return true;
    }

    private static bool TryPlanScheduledTask(DetectionFinding finding, out RemediationAction? action)
    {
        action = null;
        if (!TaskIds.Contains(finding.Id) || string.IsNullOrWhiteSpace(finding.AffectedPath)) return false;
        bool eligible = finding.Confidence is DetectionConfidence.Confirmed or DetectionConfidence.Reversed
                        && (int)finding.Severity >= (int)DetectionSeverity.High;
        if (!eligible) return false;
        action = new RemediationAction
        {
            Id = Guid.NewGuid().ToString("N"), Kind = RemediationActionKind.DeleteScheduledTask,
            FindingId = finding.Id, Title = $"Remove malicious Scheduled Task {finding.AffectedPath}",
            Severity = finding.Severity, Confidence = finding.Confidence, Target = finding.AffectedPath,
            AutoEligible = true, RequiresElevation = true,
            Reason = "Only HIGH/CRITICAL Scheduled Task command findings with Reversed/Confirmed confidence are eligible. LuckyGuard exports task XML first and refuses password-backed tasks that cannot be safely restored without collecting credentials."
        };
        return true;
    }

    private static bool TryPlanService(DetectionFinding finding, out RemediationAction? action)
    {
        action = null;
        if (!ServiceIds.Contains(finding.Id)) return false;
        string? serviceName = finding.Evidence?.FirstOrDefault(e => e.Kind.Equals("service", StringComparison.OrdinalIgnoreCase))?.Value;
        if (string.IsNullOrWhiteSpace(serviceName)) return false;
        bool eligible = finding.Confidence is DetectionConfidence.Confirmed or DetectionConfidence.Reversed
                        && finding.Severity == DetectionSeverity.Critical;
        if (!eligible) return false;
        action = new RemediationAction
        {
            Id = Guid.NewGuid().ToString("N"), Kind = RemediationActionKind.DeleteService,
            FindingId = finding.Id, Title = $"Remove malicious service {serviceName}",
            Severity = finding.Severity, Confidence = finding.Confidence, Target = serviceName,
            AutoEligible = true, RequiresElevation = true,
            Reason = "Only CRITICAL service-command findings with Reversed/Confirmed confidence are eligible. LuckyGuard requires the service to be stopped and exports its Services registry key before deletion."
        };
        return true;
    }

    private static RemediationAction CreateReviewAction(DetectionFinding finding) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        Kind = RemediationActionKind.ReviewOnly,
        FindingId = finding.Id,
        Title = $"Review: {finding.Title}",
        Severity = finding.Severity,
        Confidence = finding.Confidence,
        Target = finding.AffectedPath ?? "<no path>",
        AutoEligible = false,
        RequiresElevation = false,
        Reason = "LuckyGuard does not have enough evidence and/or rollback guarantees to mutate this finding automatically."
    };

}
