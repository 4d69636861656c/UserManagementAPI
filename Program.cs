using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UserManagementAPI.Extensions;
using UserManagementAPI.Models;

namespace UserManagementAPI;

// Minimal API setup for User Management with JWT Authentication, Caching, Logging, and Global Exception Handling.
public class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddMemoryCache();

        // Add response compression.
        builder.Services.AddResponseCompression(options =>
        {
            options.EnableForHttps = true;
            options.Providers.Add<BrotliCompressionProvider>();
            options.Providers.Add<GzipCompressionProvider>();
        });

        // Configure compression providers.
        builder.Services.Configure<BrotliCompressionProviderOptions>(options =>
        {
            options.Level = System.IO.Compression.CompressionLevel.Fastest;
        });

        builder.Services.Configure<GzipCompressionProviderOptions>(options =>
        {
            options.Level = System.IO.Compression.CompressionLevel.SmallestSize;
        });

        // Add JWT configuration section.
        builder.Services.Configure<JwtSettings>(
            builder.Configuration.GetSection("JwtSettings"));

        // Configure JWT authentication.
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
                var key = Encoding.ASCII.GetBytes(jwtSettings?.SecretKey ??
                                                  throw new InvalidOperationException(
                                                      "JWT Secret Key is not configured"));

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

                // Add debug events.
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

        // In-memory user storage using ConcurrentDictionary for thread safety.
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

        // Add global exception handling.
        app.UseGlobalExceptionHandling();

        // Add after other middleware configuration but before endpoints.
        app.UseAuthentication();
        app.UseAuthorization();

        // Add logging middleware for requests and responses.
        app.UseRequestResponseLogging();

        // Use response compression middleware.
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
            string cacheKey =
                $"users_page{page}_size{pageSize}_name{filter.Name}_email{filter.Email}_dept{filter.Department}";

            if (cache.TryGetValue(cacheKey, out PaginatedResponse<User>? cachedResponse))
            {
                return TypedResults.Ok(cachedResponse);
            }

            if (page < 1 || pageSize < 1)
                return TypedResults.BadRequest("Page and page size must be greater than 0");

            var query = users.Values.AsQueryable();

            // Apply filters.
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
        }).RequireAuthorization(); // Protect the endpoint.

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
        }).RequireAuthorization();

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
                    Infrastructure.Tools.UserCacheTools.InvalidateUserCache(cache, user.Id);
                    return TypedResults.Created($"/api/users/{user.Id}", user);
                }

                retries++;
            }

            return TypedResults.Conflict("Failed to add user due to concurrent operation. Please try again.");
        }).RequireAuthorization();

        // PUT update user
        app.MapPut("/api/users/{id}",
            Results<NotFound<string>, Ok<User>, BadRequest<List<ValidationResult>>, Conflict<string>> (
                IMemoryCache cache, int id, User updatedUser) =>
            {
                if (!users.ContainsKey(id))
                {
                    return TypedResults.NotFound("User not found");
                }

                var validationResults = new List<ValidationResult>();
                if (!Validator.TryValidateObject(updatedUser, new ValidationContext(updatedUser), validationResults,
                        true))
                {
                    return TypedResults.BadRequest(validationResults);
                }

                updatedUser.Id = id;
                if (users.TryGetValue(id, out var existingUser))
                {
                    if (users.TryUpdate(id, updatedUser, existingUser))
                    {
                        Infrastructure.Tools.UserCacheTools.InvalidateUserCache(cache, id);
                        return TypedResults.Ok(updatedUser);
                    }

                    return TypedResults.Conflict("User was modified by another request. Please try again.");
                }

                return TypedResults.NotFound("User not found");
            }).RequireAuthorization();

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
                Infrastructure.Tools.UserCacheTools.InvalidateUserCache(cache, id);
                return TypedResults.NoContent();
            }

            return TypedResults.Conflict("Failed to delete user due to concurrent operation. Please try again.");
        }).RequireAuthorization();

        // Function to generate JWT token
        app.MapPost("/api/login", (
            LoginRequest login, IOptions<JwtSettings> jwtSettings) =>
        {
            // In production, validate against your user database
            if (login.Username == "admin" && login.Password == "admin123")
            {
                var token = Infrastructure.Tools.JwtTokenTools.GenerateJwtToken(login.Username, jwtSettings.Value);
                return Results.Ok(new { token });
            }

            return Results.Unauthorized();
        });

        // Debug endpoint to inspect JWT token
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
}