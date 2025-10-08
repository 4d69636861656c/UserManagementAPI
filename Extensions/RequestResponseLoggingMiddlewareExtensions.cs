using UserManagementAPI.Infrastructure;

namespace UserManagementAPI.Extensions;

public static class RequestResponseLoggingMiddlewareExtensions
{
  public static IApplicationBuilder UseRequestResponseLogging(
    this IApplicationBuilder builder)
  {
    return builder.UseMiddleware<RequestResponseLoggingMiddleware>();
  }
}