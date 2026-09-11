namespace UnifiedGateway.Models;

/// <summary>
/// Who made a request, carried from the endpoint into the router so it can be stamped onto
/// the audit record.
///
/// Passed explicitly rather than read from an ambient HttpContext: the router is also driven
/// from tests and could later be driven from a queue, and an audit trail whose attribution
/// silently disappears outside a web request is worse than one that never had it.
/// </summary>
public record CallerContext
{
    /// <summary>Key prefix, principal ARN, or subject the caller authenticated as.</summary>
    public string? Actor { get; init; }

    /// <summary>How they authenticated: AppApiKey, AppStsToken, OktaJwt, MasterAdminKey, ...</summary>
    public string? AuthType { get; init; }

    /// <summary>jti of the STS token presented, when one was.</summary>
    public string? TokenId { get; init; }

    /// <summary>Source address as the gateway saw it.</summary>
    public string? SourceIp { get; init; }

    /// <summary>
    /// Correlation id for this request. Reused as the reference in any error returned to the
    /// caller, so a support conversation can start from the id they were shown.
    /// </summary>
    public string TraceId { get; init; } = Guid.NewGuid().ToString("N");

    /// <summary>An unattributed context, for callers that genuinely have no identity.</summary>
    public static CallerContext Anonymous() => new() { Actor = null, AuthType = "Anonymous" };

    /// <summary>
    /// Actor for a caller authenticated by an STS token. The token's callerId is whatever the
    /// minter typed, so it is carried as a bracketed label beside an identity the gateway
    /// derived itself -- the application, or break-glass for an admin token -- and never as
    /// the identity.
    /// </summary>
    public static string ActorFor(AppStsTokenPayload payload)
    {
        var identity = payload.IsAdmin ? "break-glass" : payload.AppId;
        return string.IsNullOrWhiteSpace(payload.CallerId) ? identity : $"{identity} [{payload.CallerId}]";
    }
}
