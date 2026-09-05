using System.Diagnostics;

namespace LuckyGuard.Remediation.Execution;

internal static class ProcessCommandRunner
{
    public static (int ExitCode, string StdOut, string StdErr) Run(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string arg in args) psi.ArgumentList.Add(arg);
        using Process process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {fileName}.");
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout, stderr);
    }
}
