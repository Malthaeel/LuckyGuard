namespace LuckyGuard.Remediation.Planning;

public static class RegistryLocationParser
{
    public static bool TryParseValueLocation(string? location, out RegistryLocation? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(location)) return false;
        int separator = location.LastIndexOf("::", StringComparison.Ordinal);
        if (separator <= 0 || separator >= location.Length - 2) return false;

        string keyPart = location[..separator].Replace('/', '\\').Trim();
        string valueName = location[(separator + 2)..].Trim();
        int slash = keyPart.IndexOf('\\');
        if (slash <= 0 || slash == keyPart.Length - 1 || valueName.Length == 0) return false;

        string hiveRaw = keyPart[..slash];
        string hive = hiveRaw.ToUpperInvariant() switch
        {
            "HKCU" or "CURRENTUSER" => "HKCU",
            "HKLM" or "LOCALMACHINE" => "HKLM",
            _ => string.Empty
        };
        if (hive.Length == 0) return false;
        string subKey = keyPart[(slash + 1)..];
        parsed = new RegistryLocation(hive, subKey, valueName);
        return true;
    }
}
