using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

/// <summary>
/// Per-application quotas, enforced after a credential validates (SEC-03).
///
/// The middleware limiters run before authentication and so can only key on the client address.
/// These key on the identity the credential resolved to, so every API key and STS token an
/// application holds -- and every address it calls from -- draws on one quota.
/// </summary>
public interface ICallerQuota
{
    /// <summary>Consumes one invocation for the identity; false once its window is spent.</summary>
    bool TryAcquireInvocation(string identity);

    /// <summary>Consumes one token issuance for the identity; false once its window is spent.</summary>
    bool TryAcquireIssuance(string identity);
}

public sealed class CallerQuota : ICallerQuota, IDisposable
{
    private readonly PartitionedRateLimiter<string> _invocations;
    private readonly PartitionedRateLimiter<string> _issuance;

    public CallerQuota(IOptions<GatewayOptions> options)
    {
        var security = options.Value.Security;
        _invocations = PerMinute(security.RateLimitPerMinute <= 0 ? 120 : security.RateLimitPerMinute);
        _issuance = PerMinute(security.TokenRateLimitPerMinute <= 0 ? 10 : security.TokenRateLimitPerMinute);
    }

    public bool TryAcquireInvocation(string identity) => TryAcquire(_invocations, identity);

    public bool TryAcquireIssuance(string identity) => TryAcquire(_issuance, identity);

    private static bool TryAcquire(PartitionedRateLimiter<string> limiter, string identity)
    {
        using var lease = limiter.AttemptAcquire(identity);
        return lease.IsAcquired;
    }

    // Application ids are matched case-insensitively elsewhere, so they share a bucket here too.
    private static PartitionedRateLimiter<string> PerMinute(int permitLimit) =>
        PartitionedRateLimiter.Create<string, string>(identity =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: identity.ToUpperInvariant(),
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                }));

    public void Dispose()
    {
        _invocations.Dispose();
        _issuance.Dispose();
    }
}
