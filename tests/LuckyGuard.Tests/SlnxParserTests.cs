using LuckyGuard.Solution.Parsing;

namespace LuckyGuard.Tests;

public sealed class SlnxParserTests
{
    [Fact]
    public void ParsesProjectPath()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(dir, "src"));
        try
        {
            string project = Path.Combine(dir, "src", "App.csproj");
            File.WriteAllText(project, "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            string slnx = Path.Combine(dir, "App.slnx");
            File.WriteAllText(slnx, "<Solution><Project Path=\"src/App.csproj\" /></Solution>");
            var parsed = SlnxParser.Parse(slnx);
            Assert.Single(parsed.Projects);
            Assert.Equal(Path.GetFullPath(project), parsed.Projects[0].Path);
        }
        finally { Directory.Delete(dir, true); }
    }
}
