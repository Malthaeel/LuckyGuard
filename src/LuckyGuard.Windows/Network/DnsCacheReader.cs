namespace LuckyGuard.Windows.Network;

internal static class DnsCacheReader
{
    public static IReadOnlyList<DnsCacheEntry> Read(out string? error)
    {
        error = null;
        if (!OperatingSystem.IsWindows()) return [];
        var entries = new List<DnsCacheEntry>();
        try
        {
            Type? type = Type.GetTypeFromProgID("WbemScripting.SWbemLocator");
            if (type is null) { error = "WMI locator is unavailable."; return entries; }
            dynamic locator = Activator.CreateInstance(type)!;
            dynamic services = locator.ConnectServer(".", @"root\StandardCimv2");
            foreach (dynamic item in services.ExecQuery("SELECT Name, Type, Data, Status, TimeToLive FROM MSFT_DNSClientCache"))
            {
                string name = Safe(() => item.Name) ?? string.Empty;
                string data = Safe(() => item.Data) ?? string.Empty;
                ushort typeValue = ParseUshort(Safe(() => item.Type));
                uint status = ParseUint(Safe(() => item.Status));
                uint ttl = ParseUint(Safe(() => item.TimeToLive));
                if (!string.IsNullOrWhiteSpace(name)) entries.Add(new DnsCacheEntry(name, typeValue, data, status, ttl));
            }
        }
        catch (Exception ex) { error = ex.Message; }
        return entries;
    }

    private static string? Safe(Func<object?> getter) { try { return getter()?.ToString(); } catch { return null; } }
    private static ushort ParseUshort(string? value) => ushort.TryParse(value, out var result) ? result : (ushort)0;
    private static uint ParseUint(string? value) => uint.TryParse(value, out var result) ? result : 0;
}
