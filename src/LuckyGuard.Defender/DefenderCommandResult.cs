namespace LuckyGuard.Defender;

public sealed record DefenderCommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Success => ExitCode == 0;
}
