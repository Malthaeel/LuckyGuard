namespace LuckyGuard.Windows.Network;

public sealed record DnsCacheEntry(string Name, ushort Type, string Data, uint Status, uint TimeToLive);
