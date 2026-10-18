using System;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text.Json;

namespace XboxAuthNet.XboxLive.Responses
{
    public class XboxAuthResponseHandler
    {
        public async Task<T> HandleResponse<T>(HttpResponseMessage res)
        {
            XboxSisuContext? context = null;
            var resBody = await res.Content.ReadAsStringAsync()
                .ConfigureAwait(false);

            try
            {
                if (typeof(T) == typeof(XboxSisuResponse)
                    && res.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    using var challenge = JsonDocument.Parse(resBody);
                    if (challenge.RootElement.ValueKind == JsonValueKind.Object
                        && challenge.RootElement.TryGetProperty("WebPage", out var page)
                        && page.ValueKind == JsonValueKind.String
                        && !string.IsNullOrEmpty(page.GetString()))
                        context = XboxSisuContext.FromHeaders(res.Headers);
                }
                res.EnsureSuccessStatusCode();
                var result = JsonSerializer.Deserialize<T>(resBody)
                    ?? throw new JsonException();
                if (result is XboxSisuResponse sisu)
                {
                    if (string.IsNullOrWhiteSpace(resBody) || resBody.TrimStart()[0] != '{')
                        throw new JsonException();
                    context = XboxSisuContext.FromHeaders(res.Headers);
                    sisu.Context = context;
                }
                return result;
            }
            catch (Exception ex) when (
                ex is JsonException ||
                ex is HttpRequestException)
            {
                try
                {
                    var error = XboxAuthException.FromResponseBody(resBody, (int)res.StatusCode);
                    error.SisuContext = context;
                    throw error;
                }
                catch (FormatException)
                {
                    try
                    {
                        var error = XboxAuthException.FromResponseHeaders(res.Headers, (int)res.StatusCode);
                        error.SisuContext = context;
                        throw error;
                    }
                    catch (FormatException)
                    {
                        throw new XboxAuthException($"{(int)res.StatusCode}: {res.ReasonPhrase}", (int)res.StatusCode)
                        {
                            SisuContext = context
                        };
                    }
                }
            }
        }
    }
}
