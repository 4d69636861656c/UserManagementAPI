using System.Collections;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IdentityModel.Tokens.Jwt;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace UserManagementAPI;

public class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddMemoryCache();

        // Add response compression
        builder.Services.AddResponseCompression(options =>
        {
            options.EnableForHttps = true;
            options.Providers.Add<BrotliCompressionProvider>();
            options.Providers.Add<GzipCompressionProvider>();
        });

        // Configure compression providers
        builder.Services.Configure<BrotliCompressionProviderOptions>(options =>
        {
            options.Level = System.IO.Compression.CompressionLevel.Fastest;
        });

        builder.Services.Configure<GzipCompressionProviderOptions>(options =>
        {
            options.Level = System.IO.Compression.CompressionLevel.SmallestSize;
        });

        // Add JWT configuration section
        builder.Services.Configure<JwtSettings>(
        builder.Configuration.GetSection("JwtSettings"));

        // Configure JWT authentication
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
            var key = Encoding.ASCII.GetBytes(jwtSettings?.SecretKey ?? 
                throw new InvalidOperationException("JWT Secret Key is not configured"));

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = jwtSettings.Issuer,
                ValidAudience = jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // Add debug events
            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    Console.WriteLine("Token validated successfully");
                    Console.WriteLine($"User: {context.Principal?.Identity?.Name}");
                    return Task.CompletedTask;
                },
                OnChallenge = context =>
                {
                    Console.WriteLine($"Challenge: {context.Error}, {context.ErrorDescription}");
                    return Task.CompletedTask;
                }
            };
        });

        builder.Services.AddAuthorization();

        // In-memory user storage using Dictionary
        var users = new ConcurrentDictionary<int, User>();
        users.TryAdd(1, new User { Id = 1, Name = "Alice", Email = "alice@example.com", Department = "Engineering" });
        users.TryAdd(2, new User { Id = 2, Name = "Bob", Email = "bob@example.com", Department = "HR" });
        users.TryAdd(3, new User { Id = 3, Name = "Charlie", Email = "charlie@example.com", Department = "Finance" });
        users.TryAdd(4, new User { Id = 4, Name = "Diana", Email = "diana@example.com", Department = "Marketing" });
        users.TryAdd(5, new User { Id = 5, Name = "Ethan", Email = "ethan@example.com", Department = "Sales" });
        users.TryAdd(6, new User { Id = 6, Name = "Fiona", Email = "fiona@example.com", Department = "HR" });
        users.TryAdd(7, new User { Id = 7, Name = "George", Email = "george@example.com", Department = "IT" });
        users.TryAdd(8, new User { Id = 8, Name = "Hannah", Email = "hannah@example.com", Department = "Marketing" });

        var app = builder.Build();

        app.UseHttpsRedirection();

        // Add global exception handling
        app.UseGlobalExceptionHandling();

        // Add after other middleware configuration but before endpoints
        app.UseAuthentication();
        app.UseAuthorization();

        // Add logging middleware for requests and responses
        app.UseRequestResponseLogging();

        // Use response compression middleware
        app.UseResponseCompression();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        // GET all users
        app.MapGet("/api/users", Results<Ok<PaginatedResponse<User>>, BadRequest<string>> (
            IMemoryCache cache, [AsParameters] UserFilterModel filter, 
            [FromQuery] int page = 1, [FromQuery] int pageSize = 10) =>
        {
            string cacheKey = $"users_page{page}_size{pageSize}_name{filter.Name}_email{filter.Email}_dept{filter.Department}";

            if (cache.TryGetValue(cacheKey, out PaginatedResponse<User> cachedResponse))
            {
                return TypedResults.Ok(cachedResponse);
            }

            if (page < 1 || pageSize < 1)
                return TypedResults.BadRequest("Page and page size must be greater than 0");

            var query = users.Values.AsQueryable();

            // Apply filters
            if (!string.IsNullOrWhiteSpace(filter.Name))
                query = query.Where(u => u.Name != null && 
                    u.Name.Contains(filter.Name, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Email))
                query = query.Where(u => u.Email != null && 
                    u.Email.Contains(filter.Email, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Department))
                query = query.Where(u => u.Department != null && 
                    u.Department.Contains(filter.Department, StringComparison.OrdinalIgnoreCase));

            var totalItems = query.Count();
            var items = query
                .Skip((page - 1) * pageSize)
                .Take(pageSize);

            var response = new PaginatedResponse<User>(
                items,
                page,
                pageSize,
                totalItems
            );

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetSlidingExpiration(TimeSpan.FromMinutes(5))
                .SetAbsoluteExpiration(TimeSpan.FromHours(1));

            cache.Set(cacheKey, response, cacheOptions);

            return TypedResults.Ok(response);
        }).RequireAuthorization(); // Protect the endpoint

        // GET user by ID
        app.MapGet("/api/users/{id}", Results<NotFound<string>, Ok<User>> (
            IMemoryCache cache, int id) =>
        {
            string cacheKey = $"user_{id}";

            if (cache.TryGetValue(cacheKey, out User? cachedUser))
            {
                return TypedResults.Ok(cachedUser);
            }

            if (users.TryGetValue(id, out var user))
            {
                var cacheOptions = new MemoryCacheEntryOptions()
                    .SetSlidingExpiration(TimeSpan.FromMinutes(5))
                    .SetAbsoluteExpiration(TimeSpan.FromHours(1));

                cache.Set(cacheKey, user, cacheOptions);
                return TypedResults.Ok(user);
            }

            return TypedResults.NotFound("User not found");
        });

        // POST new user
        app.MapPost("/api/users", Results<Created<User>, BadRequest<List<ValidationResult>>, Conflict<string>> (
            IMemoryCache cache, User user) =>
        {
            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(user, new ValidationContext(user), validationResults, true))
            {
                return TypedResults.BadRequest(validationResults);
            }

            int retries = 0;
            const int maxRetries = 3;
            while (retries < maxRetries)
            {
                user.Id = users.Count == 0 ? 1 : users.Max(u => u.Key) + 1;
                if (users.TryAdd(user.Id, user))
                {
                    InvalidateUserCache(cache, user.Id);
                    return TypedResults.Created($"/api/users/{user.Id}", user);
                }

                retries++;
            }

            return TypedResults.Conflict("Failed to add user due to concurrent operation. Please try again.");
        });

        // PUT update user
        app.MapPut("/api/users/{id}", Results<NotFound<string>, Ok<User>, BadRequest<List<ValidationResult>>, Conflict<string>> (
            IMemoryCache cache, int id, User updatedUser) =>
        {
            if (!users.ContainsKey(id))
            {
                return TypedResults.NotFound("User not found");
            }

            var validationResults = new List<ValidationResult>();
            if (!Validator.TryValidateObject(updatedUser, new ValidationContext(updatedUser), validationResults, true))
            {
                return TypedResults.BadRequest(validationResults);
            }

            updatedUser.Id = id;
            if (users.TryGetValue(id, out var existingUser))
            {
                if (users.TryUpdate(id, updatedUser, existingUser))
                {
                    InvalidateUserCache(cache, id);
                    return TypedResults.Ok(updatedUser);
                }

                return TypedResults.Conflict("User was modified by another request. Please try again.");
            }
            return TypedResults.NotFound("User not found");
        });

        // DELETE user
        app.MapDelete("/api/users/{id}", Results<NotFound<string>, NoContent, Conflict<string>> (
            IMemoryCache cache, int id) =>
        {
            if (!users.ContainsKey(id))
            {
                return TypedResults.NotFound("User not found");
            }

            if (users.TryRemove(id, out _))
            {
                InvalidateUserCache(cache, id);
                return TypedResults.NoContent();
            }

            return TypedResults.Conflict("Failed to delete user due to concurrent operation. Please try again.");
        });

        // Function to generate JWT token
        app.MapPost("/api/login", (
            LoginRequest login, IOptions<JwtSettings> jwtSettings) =>
        {
            // In production, validate against your user database
            if (login.Username == "admin" && login.Password == "admin123")
            {
                var token = GenerateJwtToken(login.Username, jwtSettings.Value);
                return Results.Ok(new { token });
            }

            return Results.Unauthorized();
        });

        app.MapGet("/debug-token", (HttpContext context) =>
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (string.IsNullOrEmpty(token))
                return Results.BadRequest("No token provided");

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            return Results.Ok(new
            {
                ValidFrom = jwtToken.ValidFrom,
                ValidTo = jwtToken.ValidTo,
                Issuer = jwtToken.Issuer,
                Audience = jwtToken.Audiences,
                Claims = jwtToken.Claims.Select(c => new { c.Type, c.Value })
            });
        })
        .AllowAnonymous();

        app.Run();
    }

    private static void InvalidateUserCache(IMemoryCache cache, int userId)
    {
        cache.Remove($"user_{userId}");
        // Invalidate the list cache by removing any key that starts with "users_"
        if (cache is MemoryCache memoryCache)
        {
            var allKeys = memoryCache.GetKeys<string>().Where(k => k.StartsWith("users_"));
            foreach (var key in allKeys)
            {
                cache.Remove(key);
            }
        }
    }

    private static string GenerateJwtToken(string username, JwtSettings jwtSettings)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: jwtSettings.Issuer,
            audience: jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(jwtSettings.ExpirationInMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

// Paginated response model
public record PaginatedResponse<T>(IEnumerable<T> Items, int Page, int PageSize, int TotalItems);

// Login request model
public record LoginRequest(string Username, string Password);

// User model with validation
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

public class UserFilterModel
{
    [FromQuery(Name = "name")]
    public string? Name { get; set; }

    [FromQuery(Name = "email")]
    public string? Email { get; set; }

    [FromQuery(Name = "department")]
    public string? Department { get; set; }
}

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

public class JwtSettings
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpirationInMinutes { get; set; }
}

// Add extension method for getting cache keys
public static class MemoryCacheExtensions
{
    public static IEnumerable<T> GetKeys<T>(this MemoryCache cache)
    {
        var field = typeof(MemoryCache).GetField("_entries", 
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var entries = field?.GetValue(cache) as IDictionary;
        
        return entries?.Keys.OfType<T>() ?? Enumerable.Empty<T>();
    }
}

public static class RequestResponseLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestResponseLogging(
        this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RequestResponseLoggingMiddleware>();
    }
}

public static class GlobalExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandling(
        this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<GlobalExceptionHandlingMiddleware>();
    }
}

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