using UserManagementAPI.Infrastructure;

namespace UserManagementAPI.Extensions;

public static class GlobalExceptionHandlingMiddlewareExtensions
{
  public static IApplicationBuilder UseGlobalExceptionHandling(
    this IApplicationBuilder builder)
  {
    return builder.UseMiddleware<GlobalExceptionHandlingMiddleware>();
  }
}