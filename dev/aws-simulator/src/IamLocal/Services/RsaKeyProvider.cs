using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace IamLocal.Services;

public interface IRsaKeyProvider
{
    RsaSecurityKey GetPrivateKey();
    RsaSecurityKey GetPublicKey();
    JsonWebKey GetJsonWebKey();
    string KeyId { get; }
}

public class RsaKeyProvider : IRsaKeyProvider
{
    private readonly RSA _rsa;
    private readonly string _keyId = "dev-iam-key-1";

    public string KeyId => _keyId;

    public RsaKeyProvider(IConfiguration config, ILogger<RsaKeyProvider> logger)
    {
        var keysDir = config.GetValue<string>("KeysDirectory") ?? ".keys";
        Directory.CreateDirectory(keysDir);
        var keyFilePath = Path.Combine(keysDir, "iam_rsa.pem");

        _rsa = RSA.Create(2048);

        if (File.Exists(keyFilePath))
        {
            try
            {
                var pem = File.ReadAllText(keyFilePath);
                _rsa.ImportFromPem(pem);
                logger.LogInformation("Loaded existing RSA signing key from {KeyFile}", keyFilePath);
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to load existing RSA key from {KeyFile}, generating a new one.", keyFilePath);
            }
        }

        // Generate new key and export
        var exportedPem = _rsa.ExportPkcs8PrivateKeyPem();
        try
        {
            File.WriteAllText(keyFilePath, exportedPem);
            logger.LogInformation("Generated and saved new dev RSA signing key to {KeyFile}", keyFilePath);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not persist RSA key file to {KeyFile}. Key will be held in-memory.", keyFilePath);
        }
    }

    public RsaSecurityKey GetPrivateKey()
    {
        return new RsaSecurityKey(_rsa) { KeyId = _keyId };
    }

    public RsaSecurityKey GetPublicKey()
    {
        var publicParameters = _rsa.ExportParameters(false);
        var publicRsa = RSA.Create(publicParameters);
        return new RsaSecurityKey(publicRsa) { KeyId = _keyId };
    }

    public JsonWebKey GetJsonWebKey()
    {
        var parameters = _rsa.ExportParameters(false);
        return new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.RSA,
            Use = "sig",
            Kid = _keyId,
            Alg = SecurityAlgorithms.RsaSha256,
            N = Base64UrlEncoder.Encode(parameters.Modulus),
            E = Base64UrlEncoder.Encode(parameters.Exponent)
        };
    }
}
