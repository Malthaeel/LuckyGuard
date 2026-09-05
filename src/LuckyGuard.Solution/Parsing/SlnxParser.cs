using System.Xml;
using System.Xml.Linq;
using LuckyGuard.Solution.Models;

namespace LuckyGuard.Solution.Parsing;

public static class SlnxParser
{
    public static ParsedSolution Parse(string solutionPath)
    {
        string full = Path.GetFullPath(solutionPath);
        string baseDir = Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory();

        using var reader = XmlReader.Create(full, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 16L * 1024 * 1024
        });
        var document = XDocument.Load(reader, LoadOptions.None);
        var projects = new List<SolutionProject>();

        foreach (var element in document.Descendants().Where(x => x.Name.LocalName.Equals("Project", StringComparison.OrdinalIgnoreCase)))
        {
            string? rawPath = element.Attribute("Path")?.Value ?? element.Attribute("path")?.Value;
            if (string.IsNullOrWhiteSpace(rawPath)) continue;
            string extension = Path.GetExtension(rawPath);
            if (!DeveloperFileKinds.ProjectExtensions.Contains(extension)) continue;
            string resolved = Path.GetFullPath(Path.Combine(baseDir, rawPath.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar)));
            string name = element.Attribute("Name")?.Value ?? Path.GetFileNameWithoutExtension(resolved);
            projects.Add(new SolutionProject(name, resolved));
        }

        return new ParsedSolution(full, projects);
    }
}
