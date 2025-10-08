namespace UserManagementAPI.Models;

public record PaginatedResponse<T>(IEnumerable<T> Items, int Page, int PageSize, int TotalItems);