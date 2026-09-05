using LuckyGuard.Solution.Parsing;

namespace LuckyGuard.Tests;

public sealed class SlnParserTests
{
    [Fact]
    public void ParsesReferencedProjects()
    {
        string dir = TestDir();
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "App"));
            File.WriteAllText(Path.Combine(dir, "App", "App.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            string sln = Path.Combine(dir, "Test.sln");
            File.WriteAllText(sln, "Microsoft Visual Studio Solution File, Format Version 12.00\r\nProject(\"{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}\") = \"App\", \"App\\App.csproj\", \"{11111111-1111-1111-1111-111111111111}\"\r\nEndProject\r\n");

            var parsed = SlnParser.Parse(sln);
            Assert.Single(parsed.Projects);
            Assert.Equal("App", parsed.Projects[0].Name);
            Assert.Equal(Path.GetFullPath(Path.Combine(dir, "App", "App.csproj")), parsed.Projects[0].Path);
        }
        finally { Directory.Delete(dir, true); }
    }

    private static string TestDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
