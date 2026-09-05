using System.Text.RegularExpressions;
using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Analysis;

namespace LuckyGuard.Windows.Persistence;

public static partial class ServiceImageAnalyzer
{
    public static DetectionFinding? Analyze(string serviceName, string imagePath, int startType, bool imageExists, string registryLocation)
    {
        string candidate = NormalizeImagePath(imagePath);
        if (!CommandRiskAnalyzer.IsTempPath(candidate)) return null;

        var evidence = new List<Evidence>
        {
            new("service", serviceName),
            new("imagePath", PersistenceFindingFactory.Truncate(imagePath)),
            new("normalizedPath", candidate),
            new("imageExists", imageExists.ToString()),
            new("startType", startType.ToString())
        };

        if (!imageExists && startType == 3 && LooksLikeCpuidResidue(serviceName, candidate))
        {
            return new DetectionFinding(
                "LG.PERSISTENCE.ORPHANED_CPUID_SERVICE", "Orphaned CPUID-style temporary driver service", DetectionCategory.Persistence,
                DetectionSeverity.Informational, DetectionConfidence.Heuristic,
                "A demand-start CPUID-style service entry points to a temporary driver file that no longer exists. This is typically stale service metadata, not evidence of an active LuckyWare infection.",
                registryLocation, evidence);
        }

        if (!imageExists)
        {
            return new DetectionFinding(
                "LG.PERSISTENCE.ORPHANED_TEMP_SERVICE", "Orphaned service points to missing temporary image", DetectionCategory.Persistence,
                DetectionSeverity.Suspicious, DetectionConfidence.Heuristic,
                "A service is configured to load from a temporary directory, but the configured image is missing. This can be stale software metadata or residue from a removed payload and should be reviewed.",
                registryLocation, evidence);
        }

        return new DetectionFinding(
            "LG.PERSISTENCE.SERVICE_TEMP_IMAGE", "Service image points into a temporary directory", DetectionCategory.Persistence,
            DetectionSeverity.High, DetectionConfidence.Heuristic,
            "A Windows service persists an existing executable or driver from a temporary directory.",
            registryLocation, evidence);
    }

    public static string NormalizeImagePath(string command)
    {
        string value = Environment.ExpandEnvironmentVariables(command.Trim());
        if (value.StartsWith(@"\??\", StringComparison.Ordinal)) value = value[4..];
        if (value.StartsWith(@"\\?\", StringComparison.Ordinal)) value = value[4..];
        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), value[12..]);

        if (value.StartsWith('"'))
        {
            int end = value.IndexOf('"', 1);
            if (end > 1) return value[1..end];
        }

        foreach (string extension in new[] { ".exe", ".sys", ".dll" })
        {
            int index = value.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
            if (index >= 0) return value[..(index + extension.Length)].Trim();
        }
        return value.Split(' ', 2)[0].Trim();
    }

    private static bool LooksLikeCpuidResidue(string serviceName, string path)
    {
        string file = Path.GetFileName(path);
        return CpuzServiceRegex().IsMatch(serviceName) && CpuzDriverRegex().IsMatch(file);
    }

    [GeneratedRegex("(?i)^cpuz\\d{2,4}$", RegexOptions.CultureInvariant)]
    private static partial Regex CpuzServiceRegex();

    [GeneratedRegex("(?i)^cpuz\\d{2,4}_(?:x64|x32)\\.sys$", RegexOptions.CultureInvariant)]
    private static partial Regex CpuzDriverRegex();
}
