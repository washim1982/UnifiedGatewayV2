using Amazon;
using Amazon.KeyManagementService;
using Amazon.S3;
using Amazon.SecurityToken;
using AppClients.Aws;
using AppClients.Local;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shared.Interfaces;

namespace AppClients.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAwsClients(this IServiceCollection services, IConfiguration configuration)
    {
        var localEnabled = configuration.GetValue<bool>("LocalAws:Enabled");

        if (localEnabled)
        {
            var s3Url = configuration["LocalAws:S3Url"] ?? "http://localhost:5001";
            var kmsUrl = configuration["LocalAws:KmsUrl"] ?? "http://localhost:5002";
            var stsUrl = configuration["LocalAws:StsUrl"] ?? "http://localhost:5003";

            services.AddHttpClient<IObjectStoreClient, LocalS3Client>(client =>
            {
                client.BaseAddress = new Uri(s3Url);
            });

            services.AddHttpClient<IKmsClient, LocalKmsClient>(client =>
            {
                client.BaseAddress = new Uri(kmsUrl);
            });

            services.AddHttpClient<IAuthClient, LocalIamClient>(client =>
            {
                client.BaseAddress = new Uri(stsUrl);
            });

            services.AddHttpClient<IRolesAnywhereClient, LocalRolesAnywhereClient>(client =>
            {
                client.BaseAddress = new Uri(stsUrl);
            });
        }
        else
        {
            var regionName = configuration["AWS:Region"] ?? "us-east-1";
            var region = RegionEndpoint.GetBySystemName(regionName);

            services.AddSingleton<IAmazonS3>(_ => new AmazonS3Client(region));
            services.AddSingleton<IAmazonKeyManagementService>(_ => new AmazonKeyManagementServiceClient(region));
            services.AddSingleton<IAmazonSecurityTokenService>(_ => new AmazonSecurityTokenServiceClient(region));

            services.AddSingleton<IObjectStoreClient, AwsS3Client>();
            services.AddSingleton<IKmsClient, AwsKmsClient>();
            services.AddSingleton<IAuthClient, AwsStsClient>();
        }

        return services;
    }
}
