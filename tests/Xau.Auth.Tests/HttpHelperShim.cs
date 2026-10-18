using System.Net.Http.Json;
using System.Text.Json;

namespace XboxAuthNet;

internal static class HttpHelper
{
    public const string UserAgent = "XAU-offline-contract-tests";
    public static JsonContent CreateJsonContent<T>(T obj) => JsonContent.Create(obj, mediaType: new System.Net.Http.Headers.MediaTypeHeaderValue("application/json"), options: new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull, PropertyNamingPolicy = null });
}
