using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace LuckyGuard.Windows.Network;

internal static class TcpTableNative
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int ErrorInsufficientBuffer = 122;
    private const int TcpTableOwnerPidAll = 5;

    public static IReadOnlyList<NetworkConnection> GetAllConnections()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var result = new List<NetworkConnection>();
        ReadIpv4(result);
        ReadIpv6(result);
        return result;
    }

    private static void ReadIpv4(List<NetworkConnection> result)
    {
        int size = 0;
        int rc = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
        if (rc != ErrorInsufficientBuffer && rc != 0) throw new Win32Exception(rc);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            rc = GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
            if (rc != 0) throw new Win32Exception(rc);
            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                result.Add(new NetworkConnection(
                    unchecked((int)row.OwningPid),
                    new IPAddress(BitConverter.GetBytes(row.LocalAddr)), ConvertPort(row.LocalPort),
                    new IPAddress(BitConverter.GetBytes(row.RemoteAddr)), ConvertPort(row.RemotePort), row.State, false));
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static void ReadIpv6(List<NetworkConnection> result)
    {
        int size = 0;
        int rc = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet6, TcpTableOwnerPidAll, 0);
        if (rc != ErrorInsufficientBuffer && rc != 0) return;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            rc = GetExtendedTcpTable(buffer, ref size, true, AfInet6, TcpTableOwnerPidAll, 0);
            if (rc != 0) return;
            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));
            int rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                if (row.LocalAddr is null || row.RemoteAddr is null) continue;
                result.Add(new NetworkConnection(
                    unchecked((int)row.OwningPid),
                    new IPAddress(row.LocalAddr, row.LocalScopeId), ConvertPort(row.LocalPort),
                    new IPAddress(row.RemoteAddr, row.RemoteScopeId), ConvertPort(row.RemotePort), row.State, true));
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static int ConvertPort(uint value) => (ushort)IPAddress.NetworkToHostOrder(unchecked((short)(value & 0xFFFF)));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr tcpTable, ref int size, bool order, int ipVersion, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[]? LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[]? RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }
}
