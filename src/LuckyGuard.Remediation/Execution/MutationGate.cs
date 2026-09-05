namespace LuckyGuard.Remediation.Execution;

public static class MutationGate
{
    public static bool HasConfirmation(IEnumerable<string> args, string expected)
    {
        string[] a = args.ToArray();
        for (int i = 0; i < a.Length - 1; i++)
            if (a[i].Equals("--confirm", StringComparison.OrdinalIgnoreCase)
                && a[i + 1].Equals(expected, StringComparison.Ordinal)) return true;
        return false;
    }
}
