using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;

namespace UnifiedGateway.Services;

public class STSService : ISTSService, IDisposable
{
    private readonly GatewayOptions _options;
    private readonly ISecurityService _securityService;
    private readonly ILogger<STSService> _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private AWSCredentials? _cachedCredentials;
    private DateTimeOffset? _expirationUtc;
    private string? _lastError;
    private bool _isAssumedRole;

    public STSService(
        IOptions<GatewayOptions> options,
        ISecurityService securityService,
        ILogger<STSService> logger)
    {
        _options = options.Value;
        _securityService = securityService;
        _logger = logger;
    }

    public async Task<AWSCredentials> GetCredentialsAsync(CancellationToken cancellationToken = default)
    {
        if (ShouldRefresh())
        {
            await RefreshCredentialsAsync(cancellationToken);
        }

        if (_cachedCredentials == null)
        {
            throw new InvalidOperationException($"AWS Credentials are not available. Last error: {_lastError ?? "None"}");
        }

        return _cachedCredentials;
    }

    public async Task<AwsCredentialStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var bufferMinutes = _options.Aws.RefreshBufferMinutes;
            var isExpiring = _expirationUtc.HasValue &&
                             _expirationUtc.Value <= DateTimeOffset.UtcNow.AddMinutes(bufferMinutes);

            return new AwsCredentialStatus
            {
                IsInitialized = _cachedCredentials != null,
                IsAssumedRole = _isAssumedRole,
                Region = _options.Aws.Region,
                RoleArnMasked = !string.IsNullOrEmpty(_options.Aws.AssumeRoleArn)
                    ? _securityService.MaskSecret(_options.Aws.AssumeRoleArn, 12)
                    : null,
                ProfileUsed = _options.Aws.UseLocalProfile ? _options.Aws.LocalProfileName : null,
                ExpirationUtc = _expirationUtc,
                IsExpiringSoon = isExpiring,
                LastError = _lastError
            };
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task RefreshCredentialsAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _logger.LogInformation("Refreshing AWS credentials. Region={Region}, UseLocalProfile={UseLocalProfile}",
                _options.Aws.Region, _options.Aws.UseLocalProfile);

            var regionEndpoint = RegionEndpoint.GetBySystemName(_options.Aws.Region);
            AWSCredentials? baseCredentials = null;

            if (_options.Aws.UseLocalProfile)
            {
                var profileName = string.IsNullOrWhiteSpace(_options.Aws.LocalProfileName)
                    ? "default"
                    : _options.Aws.LocalProfileName;

                _logger.LogInformation("Attempting to load local AWS profile: {ProfileName}", profileName);
                var chain = new CredentialProfileStoreChain();
                if (chain.TryGetAWSCredentials(profileName, out var profileCreds))
                {
                    baseCredentials = profileCreds;
                }
                else
                {
                    _logger.LogWarning("Profile '{ProfileName}' not found in local credentials chain. Falling back to default credential provider.", profileName);
                    baseCredentials = FallbackCredentialsFactory.GetCredentials();
                }
            }
            else
            {
                baseCredentials = FallbackCredentialsFactory.GetCredentials();
            }

            baseCredentials ??= FallbackCredentialsFactory.GetCredentials();

            // If an AssumeRoleArn is configured, assume the role via STS
            if (!string.IsNullOrWhiteSpace(_options.Aws.AssumeRoleArn))
            {
                _logger.LogInformation("Assuming AWS IAM Role: {RoleArnMasked}",
                    _securityService.MaskSecret(_options.Aws.AssumeRoleArn, 12));

                using var stsClient = new AmazonSecurityTokenServiceClient(baseCredentials, regionEndpoint);
                var assumeRequest = new AssumeRoleRequest
                {
                    RoleArn = _options.Aws.AssumeRoleArn,
                    RoleSessionName = _options.Aws.RoleSessionName,
                    DurationSeconds = _options.Aws.SessionDurationSeconds
                };

                if (!string.IsNullOrWhiteSpace(_options.Aws.ExternalId))
                {
                    assumeRequest.ExternalId = _options.Aws.ExternalId;
                }

                var response = await stsClient.AssumeRoleAsync(assumeRequest, cancellationToken);
                var creds = response.Credentials;

                _cachedCredentials = new SessionAWSCredentials(
                    creds.AccessKeyId,
                    creds.SecretAccessKey,
                    creds.SessionToken
                );

                _expirationUtc = new DateTimeOffset(creds.Expiration);
                _isAssumedRole = true;
                _lastError = null;

                _logger.LogInformation("STS AssumeRole succeeded. Session valid until: {ExpirationUtc}", _expirationUtc);
            }
            else
            {
                // Use base credentials directly
                _cachedCredentials = baseCredentials;
                _expirationUtc = null; // No fixed STS expiry on base credentials
                _isAssumedRole = false;
                _lastError = null;

                _logger.LogInformation("Using direct AWS base credentials without STS AssumeRole.");
            }
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            _logger.LogError(ex, "Failed to initialize or refresh AWS credentials");
            // If we don't have any cached credentials, rethrow
            if (_cachedCredentials == null)
            {
                throw;
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    private bool ShouldRefresh()
    {
        if (_cachedCredentials == null)
            return true;

        if (!_expirationUtc.HasValue)
            return false;

        var bufferMinutes = _options.Aws.RefreshBufferMinutes;
        return DateTimeOffset.UtcNow.AddMinutes(bufferMinutes) >= _expirationUtc.Value;
    }

    public void Dispose()
    {
        _lock.Dispose();
        GC.SuppressFinalize(this);
    }
}
