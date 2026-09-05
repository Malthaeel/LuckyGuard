using System.Runtime.InteropServices;

namespace LuckyGuard.Windows.Security;

internal static class AuthenticodeTrust
{
    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static bool? IsTrusted(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        IntPtr fileInfo = IntPtr.Zero;
        try
        {
            var file = new WintrustFileInfo(path);
            fileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
            Marshal.StructureToPtr(file, fileInfo, false);
            var data = new WintrustData(fileInfo);
            uint result = WinVerifyTrust(IntPtr.Zero, WintrustActionGenericVerifyV2, ref data);
            data.StateAction = 2; // WTD_STATEACTION_CLOSE
            _ = WinVerifyTrust(IntPtr.Zero, WintrustActionGenericVerifyV2, ref data);
            return result == 0;
        }
        catch { return null; }
        finally { if (fileInfo != IntPtr.Zero) Marshal.FreeHGlobal(fileInfo); }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionId, ref WintrustData pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
        public WintrustFileInfo(string filePath) { StructSize = (uint)Marshal.SizeOf<WintrustFileInfo>(); FilePath = filePath; FileHandle = IntPtr.Zero; KnownSubject = IntPtr.Zero; }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfoPtr;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr URLReference;
        public uint ProvFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;

        public WintrustData(IntPtr fileInfo)
        {
            StructSize = (uint)Marshal.SizeOf<WintrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SIPClientData = IntPtr.Zero;
            UIChoice = 2; // WTD_UI_NONE
            RevocationChecks = 0;
            UnionChoice = 1; // WTD_CHOICE_FILE
            FileInfoPtr = fileInfo;
            StateAction = 1; // WTD_STATEACTION_VERIFY
            StateData = IntPtr.Zero;
            URLReference = IntPtr.Zero;
            ProvFlags = 0x00000100; // WTD_REVOCATION_CHECK_NONE
            UIContext = 0;
            SignatureSettings = IntPtr.Zero;
        }
    }
}
