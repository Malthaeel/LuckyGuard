using System.Net;

namespace LuckyGuard.Ioc.Feed;

public sealed class IocFeedUpdater
{
    public const int MaxFeedBytes = 2 * 1024 * 1024;
    public const int MaxSignatureBytes = 64 * 1024;

    public async Task<IocUpdateResult> UpdateAsync(
        Uri feedUri,
        Uri signatureUri,
        string destinationFeedPath,
        string destinationSignaturePath,
        string publicKeyPath,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ValidateUri(feedUri, nameof(feedUri));
        ValidateUri(signatureUri, nameof(signatureUri));
        if (!feedUri.Host.Equals(signatureUri.Host, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Feed and signature URLs must use the same HTTPS host.");
        if (!File.Exists(publicKeyPath)) throw new FileNotFoundException("Pinned IOC public key was not found.", publicKeyPath);

        string publicKey = await File.ReadAllTextAsync(publicKeyPath, cancellationToken);
        if (!IocPublicKeyPin.IsExpected(publicKey))
            throw new InvalidDataException("Local IOC public key does not match LuckyGuard's embedded trust pin. Update refused before network access.");

        using HttpClient? ownedClient = httpClient is null ? CreateClient() : null;
        HttpClient client = httpClient ?? ownedClient ?? throw new InvalidOperationException("Could not initialize HTTP client.");

        byte[] feedBytes = await DownloadBoundedAsync(client, feedUri, MaxFeedBytes, cancellationToken);
        byte[] signatureBytes = await DownloadBoundedAsync(client, signatureUri, MaxSignatureBytes, cancellationToken);
        string signatureText = System.Text.Encoding.UTF8.GetString(signatureBytes).Trim();
        if (!IocFeedVerifier.Verify(feedBytes, signatureText, publicKey))
            throw new InvalidDataException("Downloaded IOC feed signature verification failed. Existing feed was left unchanged.");

        string feedDir = Path.GetDirectoryName(Path.GetFullPath(destinationFeedPath)) ?? Directory.GetCurrentDirectory();
        string sigDir = Path.GetDirectoryName(Path.GetFullPath(destinationSignaturePath)) ?? Directory.GetCurrentDirectory();
        if (!feedDir.Equals(sigDir, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Feed and signature destinations must be in the same directory.");
        Directory.CreateDirectory(feedDir);

        string nonce = Guid.NewGuid().ToString("N");
        string stagedFeed = Path.Combine(feedDir, $"ioc-feed.{nonce}.next.json");
        string stagedSig = Path.Combine(feedDir, $"ioc-feed.{nonce}.next.sig");
        string backupFeed = destinationFeedPath + ".bak";
        string backupSig = destinationSignaturePath + ".bak";

        try
        {
            await File.WriteAllBytesAsync(stagedFeed, feedBytes, cancellationToken);
            await File.WriteAllTextAsync(stagedSig, signatureText + Environment.NewLine, cancellationToken);

            // Parse and verify again from disk before activation. This catches write corruption and schema errors.
            VerifiedIocFeed staged = IocFeedLoader.LoadVerified(stagedFeed, stagedSig, publicKeyPath);
            if (staged.Feed.Entries.Count == 0)
                throw new InvalidDataException("Downloaded IOC feed contains zero valid entries; refusing activation.");
            if (staged.Feed.GeneratedAtUtc > DateTimeOffset.UtcNow.AddHours(24))
                throw new InvalidDataException("Downloaded IOC feed timestamp is implausibly far in the future.");
            if (File.Exists(destinationFeedPath) && File.Exists(destinationSignaturePath))
            {
                VerifiedIocFeed current = IocFeedLoader.LoadVerified(destinationFeedPath, destinationSignaturePath, publicKeyPath);
                if (staged.Feed.GeneratedAtUtc < current.Feed.GeneratedAtUtc)
                    throw new InvalidDataException($"IOC feed rollback/replay refused: downloaded feed ({staged.Feed.FeedVersion}) is older than current ({current.Feed.FeedVersion}).");
            }

            if (File.Exists(destinationFeedPath)) File.Copy(destinationFeedPath, backupFeed, overwrite: true);
            if (File.Exists(destinationSignaturePath)) File.Copy(destinationSignaturePath, backupSig, overwrite: true);

            // Replace signature first. A concurrent reader during the tiny transition window fails closed
            // because an old feed with a new signature will not verify.
            File.Move(stagedSig, destinationSignaturePath, overwrite: true);
            File.Move(stagedFeed, destinationFeedPath, overwrite: true);

            // Final verification of the activated pair. Roll back on any unexpected mismatch.
            VerifiedIocFeed activated = IocFeedLoader.LoadVerified(destinationFeedPath, destinationSignaturePath, publicKeyPath);
            return new IocUpdateResult
            {
                FeedVersion = activated.Feed.FeedVersion,
                Entries = activated.Store.Count,
                FeedPath = Path.GetFullPath(destinationFeedPath),
                SignaturePath = Path.GetFullPath(destinationSignaturePath),
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
        }
        catch
        {
            TryRestoreBackup(backupSig, destinationSignaturePath);
            TryRestoreBackup(backupFeed, destinationFeedPath);
            throw;
        }
        finally
        {
            TryDelete(stagedFeed);
            TryDelete(stagedSig);
        }
    }

    private static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    }

    private static async Task<byte[]> DownloadBoundedAsync(HttpClient client, Uri uri, int maxBytes, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if ((int)response.StatusCode is >= 300 and < 400)
            throw new HttpRequestException("IOC updater refuses HTTP redirects.");
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is long len && len > maxBytes)
            throw new InvalidDataException($"Download exceeds LuckyGuard size limit ({maxBytes} bytes).");

        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var ms = new MemoryStream();
        byte[] buffer = new byte[16 * 1024];
        int total = 0;
        while (true)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            if (read == 0) break;
            total += read;
            if (total > maxBytes) throw new InvalidDataException($"Download exceeds LuckyGuard size limit ({maxBytes} bytes).");
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
    }

    private static void ValidateUri(Uri uri, string parameter)
    {
        if (!uri.IsAbsoluteUri || !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("IOC update URLs must be absolute HTTPS URLs.", parameter);
        if (uri.IsLoopback || string.IsNullOrWhiteSpace(uri.Host))
            throw new ArgumentException("Loopback/invalid IOC update URLs are not allowed.", parameter);
    }

    private static void TryRestoreBackup(string backup, string destination)
    {
        try { if (File.Exists(backup)) File.Copy(backup, destination, overwrite: true); } catch { }
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}
