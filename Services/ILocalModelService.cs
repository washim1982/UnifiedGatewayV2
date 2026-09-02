using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public interface ILocalModelService
{
    Task<UniversalResponse> InvokeLocalModelAsync(UniversalRequest request, CancellationToken cancellationToken = default);
    Task<Dictionary<string, bool>> ProbeStatusAsync(CancellationToken cancellationToken = default);
    Task<List<string>> ListAvailableLocalModelsAsync(CancellationToken cancellationToken = default);
}
