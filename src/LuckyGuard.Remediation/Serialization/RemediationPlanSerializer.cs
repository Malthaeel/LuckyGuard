using System.Text.Json;
using System.Text.Json.Serialization;
using LuckyGuard.Remediation.Models;

namespace LuckyGuard.Remediation.Serialization;

public static class RemediationPlanSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Serialize(RemediationPlan plan) => JsonSerializer.Serialize(plan, Options);

    public static RemediationPlan Deserialize(string json)
    {
        var plan = JsonSerializer.Deserialize<RemediationPlan>(json, Options)
                   ?? throw new InvalidDataException("Remediation plan JSON is empty or invalid.");
        if (plan.SchemaVersion != 1) throw new InvalidDataException($"Unsupported remediation plan schema: {plan.SchemaVersion}.");
        return plan;
    }

    public static RemediationPlan Load(string path) => Deserialize(File.ReadAllText(path));
    public static void Save(string path, RemediationPlan plan)
    {
        string full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory());
        File.WriteAllText(full, Serialize(plan));
    }
}
