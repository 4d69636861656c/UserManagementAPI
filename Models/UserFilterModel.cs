using Microsoft.AspNetCore.Mvc;

namespace UserManagementAPI.Models;

public class UserFilterModel
{
  [FromQuery(Name = "name")] public string? Name { get; set; }

  [FromQuery(Name = "email")] public string? Email { get; set; }

  [FromQuery(Name = "department")] public string? Department { get; set; }
}