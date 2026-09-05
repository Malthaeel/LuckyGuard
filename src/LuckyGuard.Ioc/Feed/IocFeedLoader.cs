using System.Text.Json;
using System.Text.Json.Serialization;
using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Ioc.Feed;

public static class IocFeedLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static VerifiedIocFeed LoadVerified(string feedPath, string signaturePath, string publicKeyPath)
    {
        byte[] feedBytes = File.ReadAllBytes(feedPath);
        string signature = File.ReadAllText(signaturePath);
        string publicKey = File.ReadAllText(publicKeyPath);
        if (!IocPublicKeyPin.IsExpected(publicKey)) throw new InvalidDataException("IOC public key does not match LuckyGuard's embedded trust pin.");
        bool valid = IocFeedVerifier.Verify(feedBytes, signature, publicKey);
        if (!valid) throw new InvalidDataException("IOC feed signature verification failed.");

        var feed = JsonSerializer.Deserialize<IocFeed>(feedBytes, JsonOptions)
            ?? throw new InvalidDataException("IOC feed could not be parsed.");
        if (feed.SchemaVersion != 1) throw new InvalidDataException($"Unsupported IOC feed schema: {feed.SchemaVersion}.");

        var store = new IocStore();
        foreach (var entry in feed.Entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Id) || string.IsNullOrWhiteSpace(entry.Value)) continue;
            store.Add(entry);
        }

        return new VerifiedIocFeed(feed, store, true, feedPath, signaturePath, publicKeyPath);
    }

    public static (string Feed, string Signature, string PublicKey)? LocateDefault()
    {
        var bundled = LocateBundled();
        if (bundled is null) return null;

        var system = GetSystemUpdatePaths();
        if (File.Exists(system.Feed) && File.Exists(system.Signature))
        {
            // The system feed is mutable only through the elevated signed-feed updater.
            // The public key remains the bundled key and must also pass the compiled SPKI pin.
            return (system.Feed, system.Signature, bundled.Value.PublicKey);
        }

        return bundled;
    }

    public static (string Feed, string Signature, string PublicKey)? LocateBundled()
    {
        string[] roots =
        [
            AppContext.BaseDirectory,
            Directory.GetCurrentDirectory()
        ];

        foreach (string root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string dir = Path.Combine(root, "rules", "luckyware");
            string feed = Path.Combine(dir, "ioc-feed.json");
            string sig = Path.Combine(dir, "ioc-feed.sig");
            string pub = Path.Combine(dir, "ioc-public-key.pem");
            if (File.Exists(feed) && File.Exists(sig) && File.Exists(pub)) return (feed, sig, pub);
        }
        return null;
    }

    public static (string Feed, string Signature) GetSystemUpdatePaths()
    {
        string common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(common)) common = Path.GetTempPath();
        string dir = Path.Combine(common, "LuckyGuard", "Rules", "luckyware");
        return (Path.Combine(dir, "ioc-feed.json"), Path.Combine(dir, "ioc-feed.sig"));
    }
}
