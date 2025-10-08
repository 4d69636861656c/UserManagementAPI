using System.Diagnostics;

namespace UserManagementAPI.Models;

public class ApiError
{
  public int StatusCode { get; set; }
  public string Message { get; set; }
  public string? Details { get; set; }
  public string? TraceId { get; set; }

  public ApiError(string message, string? details = null, int statusCode = 500)
  {
    Message = message;
    Details = details;
    StatusCode = statusCode;
    TraceId = Activity.Current?.Id ?? "N/A";
  }
}