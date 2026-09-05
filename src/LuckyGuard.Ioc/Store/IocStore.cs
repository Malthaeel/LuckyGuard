using System.Net;
using LuckyGuard.Ioc.Models;

namespace LuckyGuard.Ioc.Store;

public sealed class IocStore
{
    private readonly Dictionary<(IocType Type, string Value), IocEntry> _entries = new();

    public int Count => _entries.Count;
    public IReadOnlyCollection<IocEntry> Entries => _entries.Values;

    public void Add(IocEntry entry) => _entries[(entry.Type, Normalize(entry.Type, entry.Value))] = entry;

    public bool TryMatch(IocType type, string value, out IocEntry? entry) =>
        _entries.TryGetValue((type, Normalize(type, value)), out entry);

    public bool TryMatchDomain(string value, out IocEntry? entry)
    {
        entry = null;
        string candidate = Normalize(IocType.Domain, value);
        if (candidate.Length == 0) return false;
        if (TryMatch(IocType.Domain, candidate, out entry)) return true;

        string[] labels = candidate.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 1; i < labels.Length - 1; i++)
        {
            string parent = string.Join('.', labels[i..]);
            if (TryMatch(IocType.Domain, parent, out entry)) return true;
        }
        return false;
    }

    private static string Normalize(IocType type, string value)
    {
        string trimmed = value.Trim();
        return type switch
        {
            IocType.Domain => trimmed.TrimEnd('.').ToLowerInvariant(),
            IocType.FileName or IocType.Sha256 => trimmed.ToLowerInvariant(),
            IocType.IpAddress => IPAddress.TryParse(trimmed, out var ip) ? ip.ToString().ToLowerInvariant() : trimmed.ToLowerInvariant(),
            _ => trimmed
        };
    }
}
