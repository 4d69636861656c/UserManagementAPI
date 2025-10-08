using System.Diagnostics;

namespace UserManagementAPI.Infrastructure;

public class RequestResponseLoggingMiddleware
{
  private readonly RequestDelegate _next;
  private readonly ILogger<RequestResponseLoggingMiddleware> _logger;

  public RequestResponseLoggingMiddleware(RequestDelegate next, ILogger<RequestResponseLoggingMiddleware> logger)
  {
    _next = next;
    _logger = logger;
  }

  public async Task InvokeAsync(HttpContext context)
  {
    var stopwatch = Stopwatch.StartNew();
    try
    {
      // Log the request
      _logger.LogInformation(
        "Request {Method} {Path} started at {Time}",
        context.Request.Method,
        context.Request.Path,
        DateTime.UtcNow);

      await _next(context);

      // Log the response
      stopwatch.Stop();
      _logger.LogInformation(
        "Request {Method} {Path} completed with status code {StatusCode} in {ElapsedMs}ms",
        context.Request.Method,
        context.Request.Path,
        context.Response.StatusCode,
        stopwatch.ElapsedMilliseconds);
    }
    catch (Exception ex)
    {
      stopwatch.Stop();
      _logger.LogError(
        ex,
        "Request {Method} {Path} failed with status code {StatusCode} in {ElapsedMs}ms",
        context.Request.Method,
        context.Request.Path,
        context.Response.StatusCode,
        stopwatch.ElapsedMilliseconds);
      throw;
    }
  }
}