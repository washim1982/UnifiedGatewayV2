namespace UnifiedGateway.Services;

/// <summary>
/// Proactively refreshes STS temporary credentials in the background before they expire.
/// </summary>
public class AwsCredentialBackgroundService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AwsCredentialBackgroundService> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(60);

    public AwsCredentialBackgroundService(
        IServiceProvider serviceProvider,
        ILogger<AwsCredentialBackgroundService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AWS Credential Refresh Background Service started.");

        // Initial warm-up attempt with retry
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var stsService = scope.ServiceProvider.GetRequiredService<ISTSService>();
            await stsService.RefreshCredentialsAsync(stoppingToken);
            _logger.LogInformation("Initial AWS credentials loaded successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Initial AWS credential initialization deferred: {Message}", ex.Message);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_checkInterval, stoppingToken);

                using var scope = _serviceProvider.CreateScope();
                var stsService = scope.ServiceProvider.GetRequiredService<ISTSService>();
                var status = await stsService.GetStatusAsync(stoppingToken);

                if (status.IsExpiringSoon || !status.IsInitialized)
                {
                    _logger.LogInformation("Proactively refreshing AWS STS credentials (Expiring: {IsExpiring})", status.IsExpiringSoon);
                    await stsService.RefreshCredentialsAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in AWS Credential Refresh Background Service loop");
            }
        }

        _logger.LogInformation("AWS Credential Refresh Background Service stopped.");
    }
}
