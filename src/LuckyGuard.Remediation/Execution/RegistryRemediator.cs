using Microsoft.Win32;

namespace LuckyGuard.Remediation.Execution;

internal static class RegistryRemediator
{
    public static RegistryValueBackup DeleteValueWithBackup(string target, string valueName, string registryView)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Registry remediation is Windows-only.");
        ParseTarget(target, out RegistryHive hive, out string subKey);
        string hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
        if (!IsAllowedRemediationLocation(hiveName, subKey, valueName))
            throw new InvalidDataException("Registry remediation target is outside LuckyGuard's allowed persistence locations.");
        RegistryView view = registryView switch
        {
            "Registry64" => RegistryView.Registry64,
            "Registry32" => RegistryView.Registry32,
            _ => throw new ArgumentException("Unsupported registry view.", nameof(registryView))
        };

        RegistryValueBackup backup;
        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view))
        using (RegistryKey? key = baseKey.OpenSubKey(subKey, writable: false))
        {
            if (key is null || !key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException("Registry value was not found in the expected registry view.");
            object? value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            RegistryValueKind kind = key.GetValueKind(valueName);
            backup = ToBackup(hive, subKey, valueName, view, kind, value);
        }

        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(subKey, writable: true);
            if (key is null) throw new InvalidOperationException($"Registry key disappeared before remediation: {backup.Hive}\\{backup.SubKey}");
            key.DeleteValue(backup.ValueName, throwOnMissingValue: true);
        }
        catch
        {
            // Best-effort restore if deletion partially completes before an exception is surfaced.
            try { Restore(backup); } catch { }
            throw;
        }

        return backup;
    }

    public static void Restore(RegistryValueBackup backup)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Registry remediation is Windows-only.");
        if (!IsAllowedRemediationLocation(backup.Hive, backup.SubKey, backup.ValueName))
            throw new InvalidDataException("Registry rollback target is outside LuckyGuard's allowed persistence locations.");
        RegistryHive hive = backup.Hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase) ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
        RegistryView view = Enum.Parse<RegistryView>(backup.View);
        RegistryValueKind kind = Enum.Parse<RegistryValueKind>(backup.Kind);
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey key = baseKey.CreateSubKey(backup.SubKey, writable: true)
            ?? throw new InvalidOperationException("Could not recreate registry key during rollback.");
        if (key.GetValueNames().Contains(backup.ValueName, StringComparer.OrdinalIgnoreCase))
            throw new IOException("Rollback target registry value is already occupied; LuckyGuard will not overwrite it.");
        key.SetValue(backup.ValueName, FromBackup(backup, kind), kind);
    }

    private static RegistryValueBackup ToBackup(RegistryHive hive, string subKey, string valueName, RegistryView view, RegistryValueKind kind, object? value)
    {
        string hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
        return kind switch
        {
            RegistryValueKind.Binary => new RegistryValueBackup
            {
                Hive = hiveName, SubKey = subKey, ValueName = valueName, View = view.ToString(), Kind = kind.ToString(), BinaryValue = value as byte[] ?? []
            },
            RegistryValueKind.MultiString => new RegistryValueBackup
            {
                Hive = hiveName, SubKey = subKey, ValueName = valueName, View = view.ToString(), Kind = kind.ToString(), StringArrayValue = value as string[] ?? []
            },
            RegistryValueKind.DWord or RegistryValueKind.QWord => new RegistryValueBackup
            {
                Hive = hiveName, SubKey = subKey, ValueName = valueName, View = view.ToString(), Kind = kind.ToString(), IntegerValue = Convert.ToInt64(value ?? 0)
            },
            _ => new RegistryValueBackup
            {
                Hive = hiveName, SubKey = subKey, ValueName = valueName, View = view.ToString(), Kind = kind.ToString(), StringValue = value?.ToString() ?? string.Empty
            }
        };
    }

    private static object FromBackup(RegistryValueBackup backup, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.Binary => backup.BinaryValue ?? [],
        RegistryValueKind.MultiString => backup.StringArrayValue ?? [],
        RegistryValueKind.DWord => Convert.ToInt32(backup.IntegerValue ?? 0),
        RegistryValueKind.QWord => backup.IntegerValue ?? 0,
        _ => backup.StringValue ?? string.Empty
    };

    internal static bool IsAllowedRemediationLocation(string hive, string subKey, string valueName)
    {
        string h = hive.ToUpperInvariant();
        string k = subKey.Replace('/', '\\').Trim('\\');
        bool run = k.Equals(@"Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)
                   || k.Equals(@"Software\Microsoft\Windows\CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase);
        if (run) return h is "HKCU" or "HKLM";

        const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\";
        return h == "HKLM"
               && k.StartsWith(ifeo, StringComparison.OrdinalIgnoreCase)
               && k.Length > ifeo.Length
               && valueName.Equals("Debugger", StringComparison.OrdinalIgnoreCase);
    }

    private static void ParseTarget(string target, out RegistryHive hive, out string subKey)
    {
        string normalized = target.Replace('/', '\\').Trim();
        int slash = normalized.IndexOf('\\');
        if (slash <= 0) throw new ArgumentException("Invalid registry target.", nameof(target));
        hive = normalized[..slash].ToUpperInvariant() switch
        {
            "HKLM" => RegistryHive.LocalMachine,
            "HKCU" => RegistryHive.CurrentUser,
            _ => throw new ArgumentException("Unsupported registry hive.", nameof(target))
        };
        subKey = normalized[(slash + 1)..];
    }
}
