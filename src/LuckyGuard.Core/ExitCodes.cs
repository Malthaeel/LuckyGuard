namespace LuckyGuard.Core;

public static class ExitCodes
{
    public const int Success = 0;
    public const int Informational = 1;
    public const int Suspicious = 2;
    public const int High = 3;
    public const int Critical = 4;
    public const int Incomplete = 10;
    public const int Failure = 20;
    public const int Usage = 64;
}
