using System.Net;

namespace UnifiedGateway.Startup;

/// <summary>
/// Refuses every request that does not come from this machine while the host runs as
/// Development (SEC-13).
///
/// StartupValidator checks the listen addresses configuration can give the host, but a host can
/// be bound in ways configuration never shows: an IIS site binding, a container port mapping,
/// code. Development auto-grants every IAM role and drops the transport and authentication
/// checks, so the one test that holds however the host was bound is the address the request
/// actually came from.
/// </summary>
public sealed class DevelopmentLoopbackMiddleware
{
    private const string Body =
        "{\"error\":{\"code\":\"LOOPBACK_ONLY\",\"message\":\"This gateway is running the Development " +
        "profile, which answers requests from this machine only.\"}}";

    private readonly RequestDelegate _next;
    private readonly ILogger<DevelopmentLoopbackMiddleware> _logger;

    public DevelopmentLoopbackMiddleware(RequestDelegate next, ILogger<DevelopmentLoopbackMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    /// <summary>True when the connection originates on this machine. An unknown address is not.</summary>
    public static bool IsLocal(ConnectionInfo connection)
    {
        if (connection.RemoteIpAddress is not { } remote)
        {
            return false;
        }

        var address = remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote;
        return IPAddress.IsLoopback(address);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (IsLocal(context.Connection))
        {
            await _next(context);
            return;
        }

        _logger.LogWarning(
            "Refused a request to {Path} from {RemoteIp}: the Development profile answers this machine only.",
            context.Request.Path, context.Connection.RemoteIpAddress);

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(Body, context.RequestAborted);
    }
}
