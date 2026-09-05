using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LuckyGuard.ServiceHost;

internal static class NativeWindowsService
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceControlShutdown = 0x00000005;
    private const int ErrorFailedServiceControllerConnect = 1063;

    private static readonly ServiceMainDelegate ServiceMainHandler = ServiceMain;
    private static readonly HandlerExDelegate ControlHandler = HandlerEx;
    private static CancellationTokenSource? _cts;
    private static IntPtr _statusHandle;
    private static int _checkpoint;

    public static int Run()
    {
        IntPtr serviceName = Marshal.StringToHGlobalUni(LuckyGuard.Guard.GuardServiceManager.ServiceName);
        int error;
        try
        {
            var table = new[]
            {
                new ServiceTableEntry { ServiceName = serviceName, ServiceMain = Marshal.GetFunctionPointerForDelegate(ServiceMainHandler) },
                new ServiceTableEntry()
            };
            if (StartServiceCtrlDispatcher(table)) return 0;
            error = Marshal.GetLastWin32Error();
        }
        finally { Marshal.FreeHGlobal(serviceName); }
        if (error == ErrorFailedServiceControllerConnect)
        {
            ServiceGuardRunner.AppendDiagnostic("Service executable was started outside the Windows Service Control Manager. Use --console for manual debugging.");
            return 64;
        }
        ServiceGuardRunner.AppendDiagnostic($"StartServiceCtrlDispatcher failed: {new Win32Exception(error).Message} ({error})");
        return 20;
    }

    private static void ServiceMain(int argc, IntPtr argv)
    {
        _statusHandle = RegisterServiceCtrlHandlerEx(LuckyGuard.Guard.GuardServiceManager.ServiceName, ControlHandler, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
        {
            ServiceGuardRunner.AppendDiagnostic($"RegisterServiceCtrlHandlerEx failed: {Marshal.GetLastWin32Error()}");
            return;
        }

        SetStatus(ServiceStartPending, 0, 10_000);
        using var cts = new CancellationTokenSource();
        _cts = cts;
        SetStatus(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, 0);
        try
        {
            ServiceGuardRunner.AppendDiagnostic("LuckyGuard Guard service started.");
            ServiceGuardRunner.RunAsync(cts.Token).GetAwaiter().GetResult();
            SetStatus(ServiceStopped, 0, 0);
        }
        catch (Exception ex)
        {
            ServiceGuardRunner.AppendDiagnostic($"Service host failure: {ex}");
            SetStatus(ServiceStopped, 0, 0, 1);
        }
        finally
        {
            if (ReferenceEquals(_cts, cts)) _cts = null;
        }
    }

    private static uint HandlerEx(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        _ = eventType; _ = eventData; _ = context;
        if (control is ServiceControlStop or ServiceControlShutdown)
        {
            SetStatus(ServiceStopPending, 0, 10_000);
            _cts?.Cancel();
        }
        return 0;
    }

    private static void SetStatus(uint state, uint acceptedControls, uint waitHint, uint win32ExitCode = 0)
    {
        if (_statusHandle == IntPtr.Zero) return;
        var status = new ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = acceptedControls,
            Win32ExitCode = win32ExitCode,
            ServiceSpecificExitCode = 0,
            CheckPoint = state is ServiceStartPending or ServiceStopPending ? (uint)Interlocked.Increment(ref _checkpoint) : 0,
            WaitHint = waitHint
        };
        SetServiceStatus(_statusHandle, ref status);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainDelegate(int argc, IntPtr argv);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerExDelegate(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceTableEntry
    {
        public IntPtr ServiceName;
        public IntPtr ServiceMain;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceStartTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerExDelegate callback, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus serviceStatus);
}
