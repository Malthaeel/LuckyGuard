using System.Text.Json;
using System.Text.Json.Serialization;
using LuckyGuard.Core.Scanning;

namespace LuckyGuard.Reporting;

public static class JsonReportWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Write(ScanResult result) => JsonSerializer.Serialize(result, Options);
}
