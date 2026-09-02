using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface IBedrockService
{
    Task<UniversalResponse> InvokeModelAsync(UniversalRequest request, CancellationToken cancellationToken = default);
    Task<bool> HealthCheckAsync(CancellationToken cancellationToken = default);
}
