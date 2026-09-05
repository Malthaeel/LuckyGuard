using System.Text.Json;

namespace LuckyGuard.Guard;

public sealed class GuardServiceConfig
{
    public int SchemaVersion { get; set; } = 1;
    public List<string> WatchRoots { get; set; } = [];
    public bool MonitorNetwork { get; set; } = true;
    public int NetworkPollSeconds { get; set; } = 30;
    public bool Verbose { get; set; }

    public GuardOptions ToOptions() => GuardOptions.CreateForRoots(WatchRoots, MonitorNetwork, Math.Clamp(NetworkPollSeconds, 5, 3600), Verbose);
}

public static class GuardServiceConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    public static string DirectoryPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LuckyGuard", "Guard");
    public static string ConfigPath => Path.Combine(DirectoryPath, "service-config.json");
    public static string LogPath => Path.Combine(DirectoryPath, "guard-service.jsonl");
    public static string DiagnosticLogPath => Path.Combine(DirectoryPath, "service-host.log");

    public static void Save(GuardServiceConfig config)
    {
        Directory.CreateDirectory(DirectoryPath);
        string temp = ConfigPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(config, JsonOptions));
        File.Move(temp, ConfigPath, overwrite: true);
    }

    public static GuardServiceConfig Load()
    {
        if (!File.Exists(ConfigPath)) return CreateDefault();
        string json = File.ReadAllText(ConfigPath);
        var config = JsonSerializer.Deserialize<GuardServiceConfig>(json, JsonOptions) ?? CreateDefault();
        if (config.SchemaVersion != 1) throw new InvalidDataException($"Unsupported Guard service config schema: {config.SchemaVersion}.");
        config.WatchRoots ??= [];
        config.NetworkPollSeconds = Math.Clamp(config.NetworkPollSeconds, 5, 3600);
        return config;
    }


    public static GuardServiceConfig LoadRequired()
    {
        if (!File.Exists(ConfigPath))
            throw new FileNotFoundException("LuckyGuard Guard service configuration is missing. Reinstall the service from an elevated terminal.", ConfigPath);
        return Load();
    }

    public static GuardServiceConfig CreateDefault(IEnumerable<string>? extraRoots = null, bool monitorNetwork = true, int networkSeconds = 30, bool verbose = false)
    {
        GuardOptions options = GuardOptions.CreateDefault(extraRoots, monitorNetwork, networkSeconds, verbose);
        return new GuardServiceConfig
        {
            WatchRoots = options.WatchRoots.ToList(),
            MonitorNetwork = options.MonitorNetwork,
            NetworkPollSeconds = (int)options.NetworkPollInterval.TotalSeconds,
            Verbose = options.Verbose
        };
    }
}
