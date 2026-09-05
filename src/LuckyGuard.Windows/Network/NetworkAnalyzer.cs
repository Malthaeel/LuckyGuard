using LuckyGuard.Core.Detection;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Scanning;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Windows.Network;

public static class NetworkAnalyzer
{
    public static IReadOnlyList<DetectionFinding> Analyze(
        NetworkConnection connection,
        string? processPath,
        bool? trustedSignature,
        IEnumerable<string> candidateDomains,
        IocStore store,
        string? feedVersion = null)
    {
        var findings = new List<DetectionFinding>();
        foreach (string domain in candidateDomains.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!store.TryMatchDomain(domain, out var domainIoc) || domainIoc is null) continue;
            findings.Add(new DetectionFinding(
                domainIoc.Confidence == DetectionConfidence.Confirmed ? "LW.NET.CONFIRMED_C2" : "LW.NET.DOMAIN_IOC_CONNECTION",
                domainIoc.Confidence == DetectionConfidence.Confirmed ? "Active connection correlates with confirmed LuckyWare C2" : "Active connection correlates with LuckyWare-associated domain IOC",
                DetectionCategory.Network,
                IocSeverityMapper.ForDirectMatch(domainIoc.Confidence), domainIoc.Confidence,
                "An active TCP connection maps through the local DNS cache to a domain in the verified LuckyGuard IOC feed.",
                processPath,
                EvidenceFor(connection, processPath, trustedSignature,
                    new[] { new Evidence("domain", domain), new Evidence("iocId", domainIoc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", domainIoc.Source) })));
            return findings;
        }

        if (store.TryMatch(IocType.IpAddress, connection.RemoteAddress.ToString(), out var ipIoc) && ipIoc is not null)
        {
            findings.Add(new DetectionFinding(
                "LW.NET.IP_IOC_CONNECTION", "Active connection matches LuckyWare-associated IP IOC", DetectionCategory.Network,
                IocSeverityMapper.ForDirectMatch(ipIoc.Confidence), ipIoc.Confidence,
                "An active TCP connection directly matches an IP address in the verified LuckyGuard IOC feed. IP indicators can be reused or reassigned, so process context is included.",
                processPath,
                EvidenceFor(connection, processPath, trustedSignature,
                    new[] { new Evidence("iocId", ipIoc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", ipIoc.Source) })));
        }
        return findings;
    }

    public static DetectionFinding? AnalyzeDnsCacheOnly(DnsCacheEntry entry, IocStore store, string? feedVersion = null)
    {
        if (!store.TryMatchDomain(entry.Name, out var ioc) || ioc is null) return null;
        return new DetectionFinding(
            "LW.NET.DNS_CACHE_IOC", "LuckyWare-associated domain is present in DNS client cache", DetectionCategory.Network,
            IocSeverityMapper.ForCacheOnly(ioc.Confidence), ioc.Confidence,
            "The Windows DNS client cache contains a LuckyWare-associated domain. Cache presence alone does not prove an active infection or current connection.",
            null,
            [new Evidence("domain", entry.Name), new Evidence("dnsData", entry.Data), new Evidence("ttl", entry.TimeToLive.ToString()), new Evidence("iocId", ioc.Id), new Evidence("feed", feedVersion ?? "unknown"), new Evidence("source", ioc.Source)]);
    }

    private static IReadOnlyList<Evidence> EvidenceFor(NetworkConnection c, string? path, bool? trusted, IEnumerable<Evidence> extra)
    {
        var evidence = new List<Evidence>
        {
            new("processId", c.ProcessId.ToString()),
            new("localEndpoint", c.LocalEndpoint),
            new("remoteEndpoint", c.RemoteEndpoint),
            new("protocol", c.IsIpv6 ? "TCP/IPv6" : "TCP/IPv4")
        };
        if (!string.IsNullOrWhiteSpace(path)) evidence.Add(new Evidence("processPath", path));
        if (trusted.HasValue) evidence.Add(new Evidence("authenticodeTrusted", trusted.Value.ToString()));
        evidence.AddRange(extra);
        return evidence;
    }
}
