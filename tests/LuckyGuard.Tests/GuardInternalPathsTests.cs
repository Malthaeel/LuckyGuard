using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardInternalPathsTests
{
    [Fact]
    public void ProgramDataLuckyGuard_IsInternal()
    {
        string path = Path.Combine(GuardInternalPaths.ProgramDataRoot, "Guard", "test.exe");
        Assert.True(GuardInternalPaths.IsInternalPath(path));
        Assert.False(GuardFileClassifier.ShouldInspect(path));
    }

    [Fact]
    public void LocalDataLuckyGuard_IsInternal()
    {
        string path = Path.Combine(GuardInternalPaths.LocalDataRoot, "Guard", "test.ps1");
        Assert.True(GuardInternalPaths.IsInternalPath(path));
        Assert.False(GuardFileClassifier.ShouldInspect(path));
    }

    [Fact]
    public void OrdinaryTempExecutable_IsNotInternal()
    {
        string path = Path.Combine(Path.GetTempPath(), "outside-luckyguard-test.exe");
        Assert.False(GuardInternalPaths.IsInternalPath(path));
        Assert.True(GuardFileClassifier.ShouldInspect(path));
    }

    [Theory]
    [InlineData("sample.jar")]
    [InlineData("sample.nupkg")]
    public void ZipCompatibleExtensions_AreWatched(string name) => Assert.True(GuardFileClassifier.ShouldInspect(Path.Combine(Path.GetTempPath(), name)));
}
