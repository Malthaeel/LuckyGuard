namespace LuckyGuard.Guard;

public sealed record GuardServiceCommandResult(bool Success, int ExitCode, string StandardOutput, string StandardError)
{
    public string Combined => string.Join(Environment.NewLine, new[] { StandardOutput.Trim(), StandardError.Trim() }.Where(x => x.Length > 0));
}
