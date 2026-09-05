using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using LuckyGuard.Core.Detection;

namespace LuckyGuard.MSBuild.Analysis;

public sealed partial class MsBuildFileAnalyzer
{
    private const int MaxImportDepth = 24;
    private const long MaxXmlCharacters = 16L * 1024 * 1024;
    private const int MaxImportedFiles = 2048;

    [GeneratedRegex(@"(?i)\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|mshta(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|curl(?:\.exe)?)\b")]
    private static partial Regex ShellRegex();
    [GeneratedRegex(@"(?i)(Invoke-WebRequest|\biwr\b|DownloadString|WebClient|https?://)")]
    private static partial Regex DownloadRegex();
    [GeneratedRegex(@"(?i)(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b)")]
    private static partial Regex ObfuscationRegex();
    [GeneratedRegex(@"(?i)(WindowStyle\s+Hidden|ExecutionPolicy\s+(Bypass|Unrestricted)|-w\s+hidden)")]
    private static partial Regex EvasionRegex();
    [GeneratedRegex(@"(?i)(%TEMP%|%APPDATA%|%LOCALAPPDATA%|\\AppData\\|\\Temp\\)")]
    private static partial Regex UserWritableRegex();

    public MsBuildAnalysisResult Analyze(IEnumerable<string> rootFiles, string? scopeRoot = null)
    {
        var result = new MsBuildAnalysisResult();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string file in rootFiles.Where(File.Exists)) AnalyzeFile(Path.GetFullPath(file), result, visited, 0, scopeRoot);
        return result;
    }

    private void AnalyzeFile(string path, MsBuildAnalysisResult result, HashSet<string> visited, int depth, string? scopeRoot)
    {
        if (depth > MaxImportDepth || visited.Count >= MaxImportedFiles || !visited.Add(path) || !File.Exists(path)) return;
        result.FilesAnalyzed.Add(path);

        XDocument document;
        try
        {
            using var reader = XmlReader.Create(path, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxXmlCharacters
            });
            document = XDocument.Load(reader, LoadOptions.SetLineInfo);
        }
        catch (Exception ex) when (ex is XmlException or IOException or UnauthorizedAccessException)
        {
            result.Errors.Add((path, ex.Message));
            return;
        }

        foreach (XElement element in document.Descendants())
        {
            string local = element.Name.LocalName;
            if (local.Equals("PreBuildEvent", StringComparison.OrdinalIgnoreCase) || local.Equals("PreLinkEvent", StringComparison.OrdinalIgnoreCase) || local.Equals("PostBuildEvent", StringComparison.OrdinalIgnoreCase))
                AnalyzeCommand(element.Value, local, path, element, result);
            else if (local.Equals("Exec", StringComparison.OrdinalIgnoreCase))
                AnalyzeCommand(element.Attribute("Command")?.Value ?? element.Value, "Exec", path, element, result);
            else if (local.Equals("Command", StringComparison.OrdinalIgnoreCase))
                AnalyzeCommand(element.Value, "Command", path, element, result);
            else if (local.Equals("UsingTask", StringComparison.OrdinalIgnoreCase))
                AnalyzeUsingTask(element, path, result);
            else if (local.Equals("Import", StringComparison.OrdinalIgnoreCase))
                AnalyzeImport(element, path, result, visited, depth, scopeRoot);
        }
    }

    private static void AnalyzeCommand(string command, string context, string path, XElement element, MsBuildAnalysisResult result)
    {
        if (string.IsNullOrWhiteSpace(command)) return;
        int score = 0;
        var evidence = new List<Evidence>();
        AddEvidence(ShellRegex(), "shell", 20);
        AddEvidence(DownloadRegex(), "download", 30);
        AddEvidence(ObfuscationRegex(), "obfuscation", 30);
        AddEvidence(EvasionRegex(), "evasion", 20);
        AddEvidence(UserWritableRegex(), "user-writable-path", 15);

        if (score < 40) return;
        DetectionSeverity severity = score >= 75 ? DetectionSeverity.High : DetectionSeverity.Suspicious;
        string id = severity == DetectionSeverity.High ? "LW.MSBUILD.SUSPICIOUS_EXECUTION_CHAIN" : "LG.MSBUILD.SUSPICIOUS_COMMAND";
        result.Findings.Add(new DetectionFinding(id, "Suspicious MSBuild command execution", DetectionCategory.MSBuild, severity, DetectionConfidence.Community, $"{context} contains a suspicious command chain (score {score}).", path, evidence));

        void AddEvidence(Regex regex, string kind, int points)
        {
            var match = regex.Match(command);
            if (!match.Success) return;
            score += points;
            evidence.Add(new Evidence(kind, match.Value, LineSource(element)));
        }
    }

    private static void AnalyzeUsingTask(XElement element, string path, MsBuildAnalysisResult result)
    {
        string taskFactory = element.Attribute("TaskFactory")?.Value ?? string.Empty;
        string assemblyFile = element.Attribute("AssemblyFile")?.Value ?? string.Empty;
        string combined = taskFactory + " " + assemblyFile + " " + element.Value;
        bool inline = combined.Contains("CodeTaskFactory", StringComparison.OrdinalIgnoreCase) || combined.Contains("RoslynCodeTaskFactory", StringComparison.OrdinalIgnoreCase);
        bool writable = UserWritableRegex().IsMatch(combined);
        if (!inline && !writable) return;
        result.Findings.Add(new DetectionFinding("LG.MSBUILD.SUSPICIOUS_USINGTASK", "Suspicious MSBuild UsingTask", DetectionCategory.MSBuild, writable ? DetectionSeverity.High : DetectionSeverity.Suspicious, DetectionConfidence.Heuristic, "UsingTask loads inline code or an assembly from a user-writable location.", path, [new Evidence("using-task", combined.Trim(), LineSource(element))]));
    }

    private void AnalyzeImport(XElement element, string currentPath, MsBuildAnalysisResult result, HashSet<string> visited, int depth, string? scopeRoot)
    {
        string? project = element.Attribute("Project")?.Value;
        if (string.IsNullOrWhiteSpace(project)) return;

        if (project.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || project.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || project.StartsWith("\\\\", StringComparison.Ordinal))
        {
            result.Findings.Add(new DetectionFinding("LG.MSBUILD.REMOTE_IMPORT", "Remote MSBuild import", DetectionCategory.MSBuild, DetectionSeverity.High, DetectionConfidence.Heuristic, "MSBuild Import references a remote/UNC location.", currentPath, [new Evidence("import", project, LineSource(element))]));
            return;
        }

        if (project.Contains("$(", StringComparison.Ordinal) || project.Contains('*') || project.Contains('?')) return;
        string resolved;
        try
        {
            resolved = Path.IsPathRooted(project) ? Path.GetFullPath(project) : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(currentPath)!, project));
        }
        catch { return; }
        if (!File.Exists(resolved)) return;

        result.ImportsFollowed++;
        AnalyzeFile(resolved, result, visited, depth + 1, scopeRoot);
    }

    private static string? LineSource(XElement element)
    {
        if (element is IXmlLineInfo line && line.HasLineInfo()) return $"line {line.LineNumber}";
        return null;
    }
}
