using System.Net;

namespace LuckyGuard.Windows.Network;

public sealed record NetworkConnection(
    int ProcessId,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    uint State,
    bool IsIpv6)
{
    public string RemoteEndpoint => $"{RemoteAddress}:{RemotePort}";
    public string LocalEndpoint => $"{LocalAddress}:{LocalPort}";
}
