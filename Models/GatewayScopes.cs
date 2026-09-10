namespace UnifiedGateway.Models;

/// <summary>
/// Scopes an application STS token can carry.
///
/// A token's scope is a restriction the API advertises, so it has to be enforced: a token
/// minted for reading must not be usable to spend money on inference. Enforcement lives in
/// <c>ApplicationRegistryService.AuthenticateAppAsync</c> and on the universal endpoint.
/// </summary>
public static class GatewayScopes
{
    /// <summary>Call a model through the gateway. The default when nothing is requested.</summary>
    public const string Invoke = "invoke";

    /// <summary>Read-only: inspect tokens and application metadata, but not invoke.</summary>
    public const string Read = "read";

    /// <summary>Administrative operations, including the universal endpoint.</summary>
    public const string Admin = "admin";

    /// <summary>Grants everything. Only mintable by the master credential.</summary>
    public const string All = "*";

    public static readonly IReadOnlySet<string> Known =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Invoke, Read, Admin, All };

    /// <summary>
    /// Normalises a requested scope string. Unknown scopes are rejected rather than silently
    /// downgraded — a caller asking for something the gateway does not understand should be
    /// told, not quietly given less than they asked for.
    /// </summary>
    public static string Normalize(string? requested)
    {
        if (string.IsNullOrWhiteSpace(requested))
        {
            return Invoke;
        }

        var parts = requested
            .Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.ToLowerInvariant())
            .Distinct()
            .ToList();

        var unknown = parts.Where(p => !Known.Contains(p)).ToList();
        if (unknown.Count > 0)
        {
            throw new ArgumentException(
                $"Unknown scope(s): {string.Join(", ", unknown)}. Valid scopes are: {string.Join(", ", Known)}.");
        }

        return string.Join(' ', parts);
    }
}
