using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json;
using UserManagementAPI.Models;

namespace UserManagementAPI.Infrastructure;

public class GlobalExceptionHandlingMiddleware
{
  private readonly RequestDelegate _next;
  private readonly ILogger<GlobalExceptionHandlingMiddleware> _logger;
  private readonly IWebHostEnvironment _env;

  public GlobalExceptionHandlingMiddleware(
    RequestDelegate next,
    ILogger<GlobalExceptionHandlingMiddleware> logger,
    IWebHostEnvironment env)
  {
    _next = next;
    _logger = logger;
    _env = env;
  }

  public async Task InvokeAsync(HttpContext context)
  {
    try
    {
      await _next(context);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "An unhandled exception occurred");
      await HandleExceptionAsync(context, ex);
    }
  }

  private async Task HandleExceptionAsync(HttpContext context, Exception ex)
  {
    context.Response.ContentType = "application/json";

    var apiError = ex switch
    {
      ValidationException validationEx =>
        new ApiError("Validation failed", validationEx.Message) { StatusCode = (int)HttpStatusCode.BadRequest },
      KeyNotFoundException notFoundEx =>
        new ApiError("Resource not found", notFoundEx.Message) { StatusCode = (int)HttpStatusCode.NotFound },
      UnauthorizedAccessException unauthorizedEx =>
        new ApiError("Unauthorized", unauthorizedEx.Message) { StatusCode = (int)HttpStatusCode.Unauthorized },
      _ => new ApiError(
          "An error occurred",
          _env.IsDevelopment() ? ex.ToString() : "Internal server error")
        { StatusCode = (int)HttpStatusCode.InternalServerError }
    };

    context.Response.StatusCode = apiError.StatusCode;

    var options = new JsonSerializerOptions
    {
      PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    await context.Response.WriteAsync(JsonSerializer.Serialize(apiError, options));
  }
}