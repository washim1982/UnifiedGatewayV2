using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface IModelRouter
{
    Task<UniversalResponse> RouteAsync(UniversalRequest request, CancellationToken cancellationToken = default);
    Task<UniversalResponse> RouteAppRequestAsync(string appId, InvokeAppRequest request, CancellationToken cancellationToken = default);
}
