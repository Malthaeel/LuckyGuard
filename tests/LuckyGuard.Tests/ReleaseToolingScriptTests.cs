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


    [Fact]
    public void PublicRepositoryIgnorePolicy_CoversSensitiveAndGeneratedArtifacts()
    {
        string root = FindRepositoryRoot();
        string gitignore = Normalize(File.ReadAllText(Path.Combine(root, ".gitignore")));
        string attributes = Normalize(File.ReadAllText(Path.Combine(root, ".gitattributes")));

        foreach (string required in new[]
        {
            "**/bin/", "**/obj/", "artifacts/", "TestResults/", "*.pfx", "*.p12", "*.key", ".env", "*.dmp", "phase*-plan.json"
        })
            Assert.Contains(required, gitignore, StringComparison.Ordinal);

        Assert.Contains("*.cmd text eol=crlf", attributes, StringComparison.Ordinal);
        Assert.Contains("* text=auto eol=lf", attributes, StringComparison.Ordinal);
        Assert.DoesNotContain("*.pem
", gitignore, StringComparison.Ordinal); // public IOC verification key must remain trackable
    }

    [Fact]
    public void ReleaseTrustEvidence_IsGeneratedAndPublished()
    {
        string root = FindRepositoryRoot();
        string release = Normalize(File.ReadAllText(Path.Combine(root, "scripts", "release.ps1")));
        string publish = Normalize(File.ReadAllText(Path.Combine(root, "scripts", "publish-github.ps1")));
        string generator = Normalize(File.ReadAllText(Path.Combine(root, "scripts", "generate-trust-evidence.ps1")));

        Assert.Contains("generate-trust-evidence.ps1", release, StringComparison.Ordinal);
        Assert.Contains("TRUST-EVIDENCE.md", publish, StringComparison.Ordinal);
        Assert.Contains("www.virustotal.com/gui/file/$sha", generator, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", generator, StringComparison.Ordinal);
        Assert.Contains("Manifest SHA-256 mismatch", generator, StringComparison.Ordinal);
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
