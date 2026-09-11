namespace UnifiedGateway.Startup;

/// <summary>
/// Refuses API requests that arrive over plain HTTP.
///
/// A redirect is the right answer for a browser opening the dashboard and the wrong one for an
/// API call: by the time the redirect goes back, the key or token has already crossed the
/// network in clear, and a client that follows it silently never learns it is misconfigured.
/// So credential-bearing paths get an error, and everything else falls through to HTTPS
/// redirection.
/// </summary>
public sealed class HttpsEnforcementMiddleware
{
    private static readonly PathString[] ApiPrefixes = ["/gateway", "/api", "/okta"];

    private const string Body =
        "{\"error\":{\"code\":\"HTTPS_REQUIRED\",\"message\":\"This API accepts HTTPS only. " +
        "Treat any credential sent over HTTP as exposed and rotate it.\"}}";

    private readonly RequestDelegate _next;
    private readonly ILogger<HttpsEnforcementMiddleware> _logger;

    public HttpsEnforcementMiddleware(RequestDelegate next, ILogger<HttpsEnforcementMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    /// <summary>True for the paths that carry API keys, STS tokens or sign-in credentials.</summary>
    public static bool IsApiPath(PathString path) =>
        ApiPrefixes.Any(prefix => path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase));

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.IsHttps || !IsApiPath(context.Request.Path))
        {
            await _next(context);
            return;
        }

        _logger.LogWarning(
            "Refused a plain-HTTP API request to {Path} from {RemoteIp}. Any credential it carried should be treated as exposed.",
            context.Request.Path, context.Connection.RemoteIpAddress);

        // 403, as IIS answers "SSL required" (403.4).
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json";
        context.Response.Headers.Connection = "close";
        await context.Response.WriteAsync(Body, context.RequestAborted);
    }
}
