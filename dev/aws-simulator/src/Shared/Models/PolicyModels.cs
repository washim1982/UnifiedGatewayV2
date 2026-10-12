using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Shared.Models;

public class PolicyStatement
{
    [JsonPropertyName("sid")]
    public string? Sid { get; set; }

    [JsonPropertyName("effect")]
    public string Effect { get; set; } = "Allow"; // "Allow" or "Deny"

    [JsonPropertyName("action")]
    [JsonConverter(typeof(SingleOrListStringConverter))]
    public List<string> Action { get; set; } = new();

    [JsonPropertyName("resource")]
    [JsonConverter(typeof(SingleOrListStringConverter))]
    public List<string> Resource { get; set; } = new();
}

public class IamPolicy
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "2012-10-17";

    [JsonPropertyName("statement")]
    [JsonConverter(typeof(SingleOrListStatementConverter))]
    public List<PolicyStatement> Statement { get; set; } = new();
}

public class IamRole
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string Arn { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<IamPolicy> Policies { get; set; } = new();

    /// <summary>
    /// Who may assume this role. Null means no trust policy, which Roles Anywhere treats as a
    /// refusal -- a role with permissions but no trust policy cannot be assumed by anyone.
    /// </summary>
    public RoleTrustPolicy? TrustPolicy { get; set; }
}

/// <summary>
/// The role's trust policy, in the shape AWS uses. Only the parts Roles Anywhere evaluates
/// are modelled.
/// </summary>
public class RoleTrustPolicy
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "2012-10-17";

    [JsonPropertyName("statement")]
    public List<TrustStatement> Statement { get; set; } = new();
}

public class TrustStatement
{
    [JsonPropertyName("sid")]
    public string? Sid { get; set; }

    [JsonPropertyName("effect")]
    public string Effect { get; set; } = "Allow";

    [JsonPropertyName("principal")]
    public TrustPrincipal Principal { get; set; } = new();

    [JsonPropertyName("action")]
    [JsonConverter(typeof(SingleOrListStringConverter))]
    public List<string> Action { get; set; } = new();

    /// <summary>e.g. { "ArnEquals": { "aws:SourceArn": "arn:aws:rolesanywhere:..." } }</summary>
    [JsonPropertyName("condition")]
    public Dictionary<string, Dictionary<string, string>>? Condition { get; set; }
}

public class TrustPrincipal
{
    [JsonPropertyName("service")]
    public string? Service { get; set; }
}

/// <summary>
/// Evaluates a role trust policy the way IAM does for Roles Anywhere.
///
/// This exists because the most common Roles Anywhere failure in production is a trust policy
/// that grants sts:AssumeRole but omits sts:TagSession or sts:SetSourceIdentity. AWS answers
/// with a bare 403 that names none of this. Reproducing that failure locally -- with a message
/// that says which action is missing -- is most of the value of simulating the service at all.
/// </summary>
public static class RoleTrustEvaluator
{
    public const string RolesAnywhereService = "rolesanywhere.amazonaws.com";

    /// <summary>All three are required; sts:AssumeRole alone is not enough.</summary>
    public static readonly string[] RequiredActions =
    [
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity"
    ];

    public static bool Allows(RoleTrustPolicy? policy, string trustAnchorArn, out string failure)
    {
        if (policy is null || policy.Statement.Count == 0)
        {
            failure = "The role has no trust policy, so nothing may assume it. Add a statement " +
                      $"allowing {RolesAnywhereService} to {string.Join(", ", RequiredActions)}.";
            return false;
        }

        foreach (var statement in policy.Statement)
        {
            if (!string.Equals(statement.Effect, "Allow", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.Equals(statement.Principal.Service, RolesAnywhereService, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var missing = RequiredActions
                .Where(required => !statement.Action.Any(granted =>
                    string.Equals(granted, required, StringComparison.OrdinalIgnoreCase) ||
                    granted == "sts:*" || granted == "*"))
                .ToList();

            if (missing.Count > 0)
            {
                failure =
                    $"The role's trust policy allows {RolesAnywhereService} but omits " +
                    $"{string.Join(" and ", missing)}. Roles Anywhere sets a source identity and " +
                    "session tags on every session, so all three actions are required.";
                return false;
            }

            // A SourceArn condition, when present, must match the anchor that vouched for the
            // certificate -- otherwise any trust anchor in the account could assume this role.
            if (statement.Condition is not null &&
                statement.Condition.TryGetValue("ArnEquals", out var arnEquals) &&
                arnEquals.TryGetValue("aws:SourceArn", out var sourceArn) &&
                !string.Equals(sourceArn, trustAnchorArn, StringComparison.OrdinalIgnoreCase))
            {
                failure =
                    $"The role's trust policy restricts aws:SourceArn to '{sourceArn}', which does " +
                    $"not match the trust anchor '{trustAnchorArn}' used for this request.";
                return false;
            }

            failure = string.Empty;
            return true;
        }

        failure =
            $"The role's trust policy contains no Allow statement for the {RolesAnywhereService} " +
            "service principal.";
        return false;
    }
}

public static class PolicyEvaluator
{
    public static bool Evaluate(IEnumerable<IamPolicy> policies, string action, string resource)
    {
        bool hasAllow = false;

        foreach (var policy in policies)
        {
            foreach (var stmt in policy.Statement)
            {
                bool actionMatches = stmt.Action.Any(a => MatchesPattern(a, action));
                bool resourceMatches = stmt.Resource.Any(r => MatchesPattern(r, resource));

                if (actionMatches && resourceMatches)
                {
                    if (string.Equals(stmt.Effect, "Deny", StringComparison.OrdinalIgnoreCase))
                    {
                        // Explicit Deny takes immediate precedence
                        return false;
                    }
                    if (string.Equals(stmt.Effect, "Allow", StringComparison.OrdinalIgnoreCase))
                    {
                        hasAllow = true;
                    }
                }
            }
        }

        return hasAllow;
    }

    public static bool MatchesPattern(string pattern, string input)
    {
        if (string.Equals(pattern, "*", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Convert wildcard pattern (* and ?) to regex
        string regexPattern = "^" + Regex.Escape(pattern)
            .Replace(@"\*", ".*")
            .Replace(@"\?", ".") + "$";

        return Regex.IsMatch(input, regexPattern, RegexOptions.IgnoreCase);
    }
}

public class SingleOrListStringConverter : JsonConverter<List<string>>
{
    public override List<string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            var str = reader.GetString();
            return str is not null ? new List<string> { str } : new List<string>();
        }
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var list = new List<string>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                if (reader.TokenType == JsonTokenType.String)
                {
                    var s = reader.GetString();
                    if (s is not null) list.Add(s);
                }
            }
            return list;
        }
        return new List<string>();
    }

    public override void Write(Utf8JsonWriter writer, List<string> value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        foreach (var item in value)
        {
            writer.WriteStringValue(item);
        }
        writer.WriteEndArray();
    }
}

public class SingleOrListStatementConverter : JsonConverter<List<PolicyStatement>>
{
    public override List<PolicyStatement> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.StartObject)
        {
            var item = JsonSerializer.Deserialize<PolicyStatement>(ref reader, options);
            return item is not null ? new List<PolicyStatement> { item } : new List<PolicyStatement>();
        }
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var list = new List<PolicyStatement>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                var item = JsonSerializer.Deserialize<PolicyStatement>(ref reader, options);
                if (item is not null) list.Add(item);
            }
            return list;
        }
        return new List<PolicyStatement>();
    }

    public override void Write(Utf8JsonWriter writer, List<PolicyStatement> value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        foreach (var item in value)
        {
            JsonSerializer.Serialize(writer, item, options);
        }
        writer.WriteEndArray();
    }
}
