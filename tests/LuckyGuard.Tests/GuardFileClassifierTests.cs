using LuckyGuard.Guard;

namespace LuckyGuard.Tests;

public sealed class GuardFileClassifierTests
{
    [Theory]
    [InlineData("sample.exe")]
    [InlineData("driver.SYS")]
    [InlineData("Game.sln")]
    [InlineData("Directory.Build.targets")]
    [InlineData("imgui_impl_win32.cpp")]
    public void ShouldInspect_RelevantSurfaces(string name) => Assert.True(GuardFileClassifier.ShouldInspect(name));

    [Theory]
    [InlineData("photo.png")]
    [InlineData("notes.txt")]
    [InlineData("movie.mp4")]
    public void ShouldInspect_IgnoresUnrelatedFiles(string name) => Assert.False(GuardFileClassifier.ShouldInspect(name));

    [Fact]
    public void DeveloperSurface_IsCaseInsensitive()
    {
        Assert.True(GuardFileClassifier.IsDeveloperSurface("GAME.VCXPROJ"));
        Assert.True(GuardFileClassifier.IsDeveloperSurface("DIRECTORY.BUILD.TARGETS"));
    }
}
