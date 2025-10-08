using Microsoft.Extensions.Caching.Memory;
using UserManagementAPI.Extensions;

namespace UserManagementAPI.Infrastructure.Tools;

internal static class UserCacheTools
{
    internal static void InvalidateUserCache(IMemoryCache cache, int userId)
    {
        cache.Remove($"user_{userId}");
        if (cache is MemoryCache memoryCache)
        {
            var allKeys = memoryCache.GetKeys<string>().Where(k => k.StartsWith("users_"));
            foreach (var key in allKeys)
            {
                cache.Remove(key);
            }
        }
    }
}