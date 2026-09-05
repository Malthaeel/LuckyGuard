using System.Security.Cryptography;
using LuckyGuard.Ioc.Feed;

namespace LuckyGuard.Tests;

public sealed class IocFeedVerifierTests
{
    [Fact]
    public void ValidEcdsaSignature_Verifies()
    {
        byte[] data = "{\"schemaVersion\":1}"u8.ToArray();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signature = key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        string pem = key.ExportSubjectPublicKeyInfoPem();
        Assert.True(IocFeedVerifier.Verify(data, Convert.ToBase64String(signature), pem));
    }

    [Fact]
    public void ModifiedData_FailsVerification()
    {
        byte[] data = "original"u8.ToArray();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signature = key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(IocFeedVerifier.Verify("changed"u8.ToArray(), Convert.ToBase64String(signature), key.ExportSubjectPublicKeyInfoPem()));
    }
}
