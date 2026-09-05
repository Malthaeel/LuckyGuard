namespace LuckyGuard.Core.Configuration;

public static class ReleaseVersionPolicy
{
    public static bool IsNewerStableRelease(string currentVersion, string latestTag)
    {
        static bool TryCore(string value, out Version version, out bool prerelease)
        {
            value = value.Trim();
            if (value.StartsWith('v') || value.StartsWith('V')) value = value[1..];
            int dash = value.IndexOf('-');
            prerelease = dash >= 0;
            string core = dash >= 0 ? value[..dash] : value;
            bool ok = Version.TryParse(core, out Version? parsed);
            version = parsed ?? new Version(0, 0);
            return ok;
        }

        if (!TryCore(currentVersion, out Version current, out bool currentPre)
            || !TryCore(latestTag, out Version latest, out bool latestPre)
            || latestPre) return false;

        int compare = latest.CompareTo(current);
        return compare > 0 || (compare == 0 && currentPre);
    }
}
