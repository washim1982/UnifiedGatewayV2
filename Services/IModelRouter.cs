using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface IModelRouter
{
    /// <summary>
    /// Routes a direct request. <paramref name="caller"/> is stamped onto the audit record;
    /// omitting it produces an unattributed line, which is only correct when there really
    /// is no identity.
    /// </summary>
    Task<UniversalResponse> RouteAsync(
        UniversalRequest request,
        CallerContext? caller = null,
        CancellationToken cancellationToken = default);

    Task<UniversalResponse> RouteAppRequestAsync(
        string appId,
        InvokeAppRequest request,
        CallerContext? caller = null,
        CancellationToken cancellationToken = default);
}
