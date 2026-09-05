using System.Text.Json;

namespace LuckyGuard.Core.Configuration;

public static class ConfigLoader
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip };

    public static LuckyGuardConfig Load(string? path = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return new LuckyGuardConfig();
        string json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<LuckyGuardConfig>(json, Options) ?? new LuckyGuardConfig();
    }
}
