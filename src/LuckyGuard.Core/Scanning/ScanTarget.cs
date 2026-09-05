namespace LuckyGuard.Core.Scanning;

public sealed record ScanTarget(ScanTargetKind Kind, string Value)
{
    public string FullPath => Kind == ScanTargetKind.System ? Value : Path.GetFullPath(Value);
}
