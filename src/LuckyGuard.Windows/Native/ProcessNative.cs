using System.Runtime.InteropServices;

namespace LuckyGuard.Windows.Native;

internal static class ProcessNative
{
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessCommandLineInformation = 60;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    public static Dictionary<int, int> GetParentMap()
    {
        var map = new Dictionary<int, int>();
        if (!OperatingSystem.IsWindows()) return map;
        IntPtr snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == InvalidHandleValue) return map;
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry)) return map;
            do
            {
                map[(int)entry.ProcessId] = (int)entry.ParentProcessId;
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            } while (Process32Next(snapshot, ref entry));
        }
        finally { CloseHandle(snapshot); }
        return map;
    }

    public static string? QueryImagePath(int pid)
    {
        if (!OperatingSystem.IsWindows()) return null;
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            int size = 32768;
            var buffer = new char[size];
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
        }
        finally { CloseHandle(handle); }
    }

    public static string? QueryCommandLine(int pid)
    {
        if (!OperatingSystem.IsWindows()) return null;
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint required = 0;
            _ = NtQueryInformationProcess(handle, ProcessCommandLineInformation, IntPtr.Zero, 0, out required);
            if (required == 0 || required > 1024 * 1024) return null;
            buffer = Marshal.AllocHGlobal((int)required);
            int status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, buffer, required, out _);
            if (status < 0) return null;
            var value = Marshal.PtrToStructure<UnicodeString>(buffer);
            if (value.Buffer == IntPtr.Zero || value.Length == 0) return string.Empty;
            return Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
        }
        catch { return null; }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, [Out] char[] exeName, ref int size);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, out uint returnLength);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size; public uint Usage; public uint ProcessId; public IntPtr DefaultHeapId; public uint ModuleId; public uint Threads; public uint ParentProcessId; public int PriClassBase; public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string? ExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
}
