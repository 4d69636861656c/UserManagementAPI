using System.ComponentModel.DataAnnotations;

namespace UserManagementAPI.Models;

public class User
{
  public int Id { get; set; }

  [Required(ErrorMessage = "Name is required")]
  [StringLength(100, MinimumLength = 2, ErrorMessage = "Name must be between 2 and 100 characters")]
  public string? Name { get; set; }

  [Required(ErrorMessage = "Email is required")]
  [EmailAddress(ErrorMessage = "Invalid email address format")]
  [StringLength(255, ErrorMessage = "Email cannot exceed 255 characters")]
  public string? Email { get; set; }

  [Required(ErrorMessage = "Department is required")]
  [StringLength(50, ErrorMessage = "Department cannot exceed 50 characters")]
  public string? Department { get; set; }
}