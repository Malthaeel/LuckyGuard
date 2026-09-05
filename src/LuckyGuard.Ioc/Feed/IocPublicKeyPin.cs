using System.Security.Cryptography;

namespace LuckyGuard.Ioc.Feed;

public static class IocPublicKeyPin
{
    // SHA-256 over DER SubjectPublicKeyInfo, not the PEM text. Line-ending changes do not affect the pin.
    public const string ExpectedSpkiSha256 = "3D7738F1C5E21926B9DCA3ED7A72D8E14A82BBA97945000EE263FD582EF97209";

    public static bool IsExpected(string publicKeyPem)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem);
            byte[] spki = key.ExportSubjectPublicKeyInfo();
            string actual = Convert.ToHexString(SHA256.HashData(spki));
            return actual.Equals(ExpectedSpkiSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch (CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
        catch (FormatException) { return false; }
    }
}
