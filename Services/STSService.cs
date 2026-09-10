using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Microsoft.Extensions.Options;
using UnifiedGateway.Models;
using UnifiedGateway.Services.Aws;

namespace UnifiedGateway.Services;

public class STSService : ISTSService, IDisposable
{
    private readonly GatewayOptions _options;
    private readonly ISecurityService _securityService;
    private readonly IRolesAnywhereCredentialProvider? _rolesAnywhere;
    private readonly ILogger<STSService> _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private AWSCredentials? _cachedCredentials;
    private DateTimeOffset? _expirationUtc;
    private string? _lastError;
    private bool _isAssumedRole;
    private string? _subjectArn;

    public STSService(
        IOptions<GatewayOptions> options,
        ISecurityService securityService,
        ILogger<STSService> logger,
        IRolesAnywhereCredentialProvider? rolesAnywhere = null)
    {
        _options = options.Value;
        _securityService = securityService;
        _logger = logger;
        _rolesAnywhere = rolesAnywhere;
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

            var source = _options.Aws.EffectiveCredentialSource;

            var roleArn = source == AwsCredentialSource.RolesAnywhere
                ? _options.Aws.RolesAnywhere.RoleArn
                : _options.Aws.AssumeRoleArn;

            // Reported so an operator can see which certificate this host presents and when
            // it expires -- a Roles Anywhere deployment fails on certificate lifecycle far
            // more often than on anything else, and it fails everywhere at once.
            RolesAnywhereCertificateInfo? certificate = null;
            if (source == AwsCredentialSource.RolesAnywhere && _rolesAnywhere is not null)
            {
                try
                {
                    certificate = _rolesAnywhere.DescribeCertificate();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Could not describe the Roles Anywhere certificate.");
                }
            }

            return new AwsCredentialStatus
            {
                IsInitialized = _cachedCredentials != null,
                IsAssumedRole = _isAssumedRole,
                Region = _options.Aws.Region,
                CredentialSource = source.ToString(),
                RoleArnMasked = string.IsNullOrEmpty(roleArn)
                    ? null
                    : _securityService.MaskSecret(roleArn, 12),
                ProfileUsed = source == AwsCredentialSource.LocalProfile
                    ? _options.Aws.LocalProfileName
                    : null,
                SubjectArnMasked = string.IsNullOrEmpty(_subjectArn)
                    ? null
                    : _securityService.MaskSecret(_subjectArn, 12),
                Certificate = certificate,
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
            var source = _options.Aws.EffectiveCredentialSource;

            _logger.LogInformation("Refreshing AWS credentials. Region={Region}, Source={Source}",
                _options.Aws.Region, source);

            var regionEndpoint = RegionEndpoint.GetBySystemName(_options.Aws.Region);
            AWSCredentials? baseCredentials = null;

            // Roles Anywhere yields credentials for the target role directly, so it neither
            // needs base credentials nor a subsequent AssumeRole. It returns here.
            if (source == AwsCredentialSource.RolesAnywhere)
            {
                if (_rolesAnywhere is null)
                {
                    throw new InvalidOperationException(
                        "Gateway:Aws:CredentialSource is 'RolesAnywhere' but no Roles Anywhere provider " +
                        "was registered. This is a wiring fault, not a configuration one.");
                }

                var (rolesAnywhereCredentials, expiration, subjectArn) =
                    await _rolesAnywhere.CreateSessionAsync(cancellationToken);

                _cachedCredentials = rolesAnywhereCredentials;
                _expirationUtc = expiration;
                _isAssumedRole = true;
                _subjectArn = subjectArn;
                _lastError = null;

                _logger.LogInformation(
                    "AWS credentials obtained via IAM Roles Anywhere. Valid until {ExpirationUtc:O}.",
                    _expirationUtc);

                return;
            }

            if (source == AwsCredentialSource.LocalProfile)
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
