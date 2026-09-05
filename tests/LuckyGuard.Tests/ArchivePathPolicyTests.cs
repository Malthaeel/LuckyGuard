using LuckyGuard.Archive;

namespace LuckyGuard.Tests;

public sealed class ArchivePathPolicyTests
{
    [Theory]
    [InlineData("../evil.exe")]
    [InlineData("a/../../evil.exe")]
    [InlineData("/absolute/evil.exe")]
    [InlineData("\\absolute\\evil.exe")]
    [InlineData("//server/share/evil.exe")]
    [InlineData("C:/evil.exe")]
    public void TraversalLikePaths_AreRejected(string path) => Assert.True(ArchivePathPolicy.IsTraversalLike(path));

    [Theory]
    [InlineData("safe/file.txt")]
    [InlineData("folder/sub/file.exe")]
    [InlineData("..notparent/file.txt")]
    public void SafeRelativePaths_AreAccepted(string path) => Assert.False(ArchivePathPolicy.IsTraversalLike(path));
}
