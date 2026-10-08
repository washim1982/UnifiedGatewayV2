namespace UnifiedGateway.Startup;

/// <summary>
/// Partition keys for the rate limiters that run before authentication (SEC-03).
///
/// Nothing a request says about itself -- an API key, a token, an appId -- may choose its
/// bucket: those are checked later or not at all, so a caller who varied the string got a fresh
/// bucket on every request. The connection's address is the one input the caller does not
/// write. Once a credential validates, <see cref="Services.ICallerQuota"/> applies a second limit
/// keyed by the application it belongs to.
///
/// Behind a reverse proxy every caller shares the proxy's address. Configure forwarded headers
/// with KnownProxies before putting one in front.
/// </summary>
public static class RateLimitPartitions
{
    public static string ForClient(HttpContext context) =>
        "ip:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
}
