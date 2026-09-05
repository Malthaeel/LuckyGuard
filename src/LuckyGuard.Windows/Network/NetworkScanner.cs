using System.Net;
using LuckyGuard.Core.Detection;
using LuckyGuard.Core.Scanning;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;
using LuckyGuard.Windows.Native;
using LuckyGuard.Windows.Security;

namespace LuckyGuard.Windows.Network;

public sealed class NetworkScanner(IocStore store, string? feedVersion = null) : IScanner
{
    public string Name => "NetworkScanner";
    public bool CanScan(ScanTarget target) => target.Kind == ScanTargetKind.System &&
        (target.Value.Equals("network", StringComparison.OrdinalIgnoreCase) || target.Value.Equals("system", StringComparison.OrdinalIgnoreCase));

    public Task ScanAsync(ScanContext context, ScanResult result)
    {
        if (!OperatingSystem.IsWindows()) { result.Notes.Add("Network scanner is Windows-only."); return Task.CompletedTask; }
        if (store.Count == 0)
        {
            result.Errors.Add(new ScanError(Name, "Verified IOC feed is unavailable; network IOC coverage is incomplete."));
            return Task.CompletedTask;
        }

        IReadOnlyList<NetworkConnection> connections;
        try { connections = TcpTableNative.GetAllConnections(); }
        catch (Exception ex) { result.Errors.Add(new ScanError(Name, ex.Message)); return Task.CompletedTask; }

        var dnsEntries = DnsCacheReader.Read(out string? dnsError);
        if (!string.IsNullOrWhiteSpace(dnsError))
        {
            result.Notes.Add($"DNS cache correlation unavailable: {dnsError}");
            result.Metrics["dnsCacheCoverage"] = 0;
        }
        else result.Metrics["dnsCacheCoverage"] = 1;

        var ipToDomains = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var matchedCacheDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in dnsEntries)
        {
            if ((entry.Type == 1 || entry.Type == 28) && IPAddress.TryParse(entry.Data, out var address))
            {
                string key = address.ToString();
                if (!ipToDomains.TryGetValue(key, out var names)) ipToDomains[key] = names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                names.Add(entry.Name);
            }
            if (store.TryMatchDomain(entry.Name, out _)) matchedCacheDomains.Add(entry.Name);
        }

        int active = 0, correlated = 0, processPaths = 0, trusted = 0;
        var activeIocDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var connection in connections)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (connection.RemotePort == 0 || IsUnspecified(connection.RemoteAddress)) continue;
            active++;
            string? path = ProcessNative.QueryImagePath(connection.ProcessId);
            if (path is not null) processPaths++;
            bool? signer = path is not null ? AuthenticodeTrust.IsTrusted(path) : null;
            if (signer == true) trusted++;
            IEnumerable<string> domains = ipToDomains.TryGetValue(connection.RemoteAddress.ToString(), out var mapped) ? mapped : Array.Empty<string>();
            var findings = NetworkAnalyzer.Analyze(connection, path, signer, domains, store, feedVersion);
            if (findings.Count > 0)
            {
                correlated++;
                foreach (string domain in domains) if (store.TryMatchDomain(domain, out _)) activeIocDomains.Add(domain);
                result.Findings.AddRange(findings);
            }
        }

        foreach (var entry in dnsEntries)
        {
            if (activeIocDomains.Contains(entry.Name)) continue;
            var finding = NetworkAnalyzer.AnalyzeDnsCacheOnly(entry, store, feedVersion);
            if (finding is not null && result.Findings.All(f => f.Id != finding.Id || f.Evidence?.FirstOrDefault(e => e.Kind == "domain")?.Value != entry.Name))
                result.Findings.Add(finding);
        }

        result.Metrics["tcpRowsEnumerated"] = connections.Count;
        result.Metrics["activeTcpConnectionsInspected"] = active;
        result.Metrics["networkIocConnections"] = correlated;
        result.Metrics["dnsCacheEntriesInspected"] = dnsEntries.Count;
        result.Metrics["dnsIocNamesObserved"] = matchedCacheDomains.Count;
        result.Metrics["networkProcessPathsResolved"] = processPaths;
        result.Metrics["networkTrustedSignatures"] = trusted;
        result.Notes.Add("Network inspection is read-only. Domain matches use the local Windows DNS client cache; DNS-cache-only findings are lower severity because cache presence does not prove active malware traffic.");

        // A successful standalone network pass is an assessed surface even when no IOC matches are found.
        // Without this transition VerdictResolver intentionally preserves NotAssessed.
        NetworkScanCompletion.MarkAssessed(result);

        return Task.CompletedTask;
    }

    private static bool IsUnspecified(IPAddress address) => IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address) || IPAddress.None.Equals(address);
}
