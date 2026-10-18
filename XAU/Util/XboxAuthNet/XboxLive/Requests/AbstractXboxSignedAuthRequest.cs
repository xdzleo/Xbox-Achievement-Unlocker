using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.Responses;

namespace XboxAuthNet.XboxLive.Requests;

public abstract class AbstractXboxSignedAuthRequest
{
    public XboxAuthResponseHandler ResponseHandler { get; set; } = new();
    protected abstract string RequestUrl { get; }
    protected virtual string Token { get; } = "";

    public async Task<T> Send<T>(HttpClient httpClient, IXboxRequestSigner signer)
    {
        if (ResponseHandler == null)
            throw new InvalidOperationException("ResponseHandler was null");

        var request = buildRequest(signer);
        var response = await httpClient.SendAsync(request);
        return await ResponseHandler.HandleResponse<T>(response);
    }

    private HttpRequestMessage buildRequest(IXboxRequestSigner signer)
    {
        var body = BuildBody(signer.ProofKey);
        var bodyStr = JsonSerializer.Serialize(body, new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });

        var req = new HttpRequestMessage
        {
            RequestUri = new Uri(RequestUrl),
            Method = HttpMethod.Post,
            Content = new StringContent(bodyStr, Encoding.UTF8, "application/json")
        };

        var signature = signer.SignRequest(RequestUrl, Token, bodyStr);
        req.Headers.Add("Signature", signature);
        // Xbox authentication endpoints reject signed requests without the
        // protocol contract header. The unsigned base request already adds
        // this header; signed requests must carry the same version explicitly.
        req.Headers.Add("x-xbl-contract-version", "1");
        CommonRequestHeaders.AddDefaultHeaders(req);
        return req;
    }

    protected abstract object BuildBody(object proofKey);
}
