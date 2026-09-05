using LuckyGuard.MSBuild.Discovery;

namespace LuckyGuard.Tests;

public sealed class ParentBuildFileDiscoveryTests
{
    [Fact]
    public void FindsDirectoryBuildTargetsAboveProject()
    {
        string root = Path.Combine(Path.GetTempPath(), "LuckyGuardTests", Guid.NewGuid().ToString("N"));
        string nested = Path.Combine(root, "src", "App");
        Directory.CreateDirectory(nested);
        try
        {
            string targets = Path.Combine(root, "Directory.Build.targets");
            File.WriteAllText(targets, "<Project />");
            var found = ParentBuildFileDiscovery.Discover(nested);
            Assert.Contains(Path.GetFullPath(targets), found, StringComparer.OrdinalIgnoreCase);
        }
        finally { Directory.Delete(root, true); }
    }
}
