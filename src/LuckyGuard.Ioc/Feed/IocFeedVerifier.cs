using System.Security.Cryptography;

namespace LuckyGuard.Ioc.Feed;

public static class IocFeedVerifier
{
    public static bool Verify(byte[] feedBytes, string signatureBase64, string publicKeyPem)
    {
        if (feedBytes.Length == 0 || string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(publicKeyPem))
            return false;

        byte[] signature;
        try { signature = Convert.FromBase64String(signatureBase64.Trim()); }
        catch (FormatException) { return false; }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);
            return ecdsa.VerifyData(feedBytes, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
