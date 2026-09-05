namespace LuckyGuard.Tests;

public sealed class ReleaseToolingScriptTests
{
    [Fact]
    public void PowerShellChildScripts_DoNotDependOnLastExitCode()
    {
        string root = FindRepositoryRoot();
        string bootstrap = Normalize(File.ReadAllText(Path.Combine(root, "scripts", "github-bootstrap.ps1")));
        string release = Normalize(File.ReadAllText(Path.Combine(root, "scripts", "release.ps1")));

        Assert.Contains("& (Join-Path $PSScriptRoot 'configure-public.ps1') -Repository $repository\nif(-not $?)", bootstrap);
        Assert.DoesNotContain("configure-public.ps1') -Repository $repository\nif($LASTEXITCODE", bootstrap);

        Assert.Contains("sign-artifacts.ps1') -Path $payload", release);
        Assert.Contains("if (-not $?) { throw 'Payload signing failed.' }", release);
        Assert.Contains("if (-not $?) { throw 'Installer signing failed.' }", release);
        Assert.DoesNotContain("if ($LASTEXITCODE -ne 0) { throw 'Payload signing failed.' }", release);
        Assert.DoesNotContain("if ($LASTEXITCODE -ne 0) { throw 'Installer signing failed.' }", release);
    }

    private static string Normalize(string value) => value.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "LuckyGuard.sln")))
                return directory.FullName;
            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("LuckyGuard repository root was not found.");
    }
}
