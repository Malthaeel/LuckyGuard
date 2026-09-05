using LuckyGuard.Guard;

namespace LuckyGuard.ServiceHost;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 20;
        if (args.Any(a => a.Equals("--console", StringComparison.OrdinalIgnoreCase)))
            return RunConsoleAsync().GetAwaiter().GetResult();
        return NativeWindowsService.Run();
    }

    private static async Task<int> RunConsoleAsync()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        await ServiceGuardRunner.RunAsync(cts.Token, requireConfig: false);
        return 0;
    }
}
