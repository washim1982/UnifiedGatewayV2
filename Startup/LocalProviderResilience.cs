using Polly;
using Polly.Extensions.Http;

namespace UnifiedGateway.Startup;

/// <summary>
/// Resilience policies for the on-prem model backends (Ollama, LM Studio, llama.cpp).
///
/// Two rules the shared policies used to break (SL-17 in docs/security-architecture-flow.md):
/// each backend gets its own circuit breaker, so one dead host does not open the circuit for
/// the others; and only idempotent requests are retried, so a generation POST that timed out
/// is not run a second time on a model that may still be answering the first.
/// </summary>
public static class LocalProviderResilience
{
    /// <summary>Retries transient failures twice, backing off 400 ms then 800 ms.</summary>
    public static IAsyncPolicy<HttpResponseMessage> BuildRetryPolicy() =>
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .Or<TimeoutException>()
            .WaitAndRetryAsync(2, attempt => TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt)));

    /// <summary>
    /// A fresh breaker. Call once per named client: a single instance shared by every backend
    /// means one failing host trips the circuit for all of them.
    /// </summary>
    public static IAsyncPolicy<HttpResponseMessage> BuildCircuitBreaker() =>
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .CircuitBreakerAsync(
                handledEventsAllowedBeforeBreaking: 5,
                durationOfBreak: TimeSpan.FromSeconds(30));

    /// <summary>
    /// True when re-sending the request is safe. A generation POST is not: it may have reached
    /// the model and be running, so a retry burns a second generation, bills the application
    /// twice, and can return the slower of two answers.
    /// </summary>
    public static bool IsRetryable(HttpRequestMessage request) =>
        request.Method == HttpMethod.Get ||
        request.Method == HttpMethod.Head ||
        request.Method == HttpMethod.Options;
}
