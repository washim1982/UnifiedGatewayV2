using System.Text.Json;

namespace UnifiedGateway.Services.Cloud;

/// <summary>
/// The local policy evaluators understand Effect, Principal, Action and Resource only. A
/// statement that restricts access any other way -- a Condition, or NotAction, NotResource or
/// NotPrincipal -- would be read as if the restriction were not there, so a policy carrying one
/// is refused outright rather than evaluated more permissively than it was written (SEC-01).
/// </summary>
public static class PolicyDocumentGuard
{
    private static readonly string[] UnsupportedElements = ["Condition", "NotAction", "NotResource", "NotPrincipal"];

    /// <summary>Returns the first unsupported element used by any statement, or null when there is none.</summary>
    public static string? FindUnsupportedElement(IEnumerable<JsonElement> statements)
    {
        foreach (var statement in statements)
        {
            if (statement.ValueKind != JsonValueKind.Object) continue;

            foreach (var property in statement.EnumerateObject())
            {
                var element = Array.Find(UnsupportedElements,
                    e => string.Equals(e, property.Name, StringComparison.OrdinalIgnoreCase));

                if (element is not null) return element;
            }
        }

        return null;
    }
}
