using System.Collections;
using Microsoft.Extensions.Caching.Memory;

namespace UserManagementAPI.Extensions;

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