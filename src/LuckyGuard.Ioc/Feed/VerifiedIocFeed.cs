using LuckyGuard.Ioc.Models;
using LuckyGuard.Ioc.Store;

namespace LuckyGuard.Ioc.Feed;

public sealed record VerifiedIocFeed(
    IocFeed Feed,
    IocStore Store,
    bool SignatureValid,
    string FeedPath,
    string SignaturePath,
    string PublicKeyPath);
