using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using XboxAuthNet;
using XboxAuthNet.XboxLive;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.Requests;
using XboxAuthNet.XboxLive.Responses;

internal static class Program
{
    private static int _passed;

    public static async Task<int> Main()
    {
        await Run("signed XSTS serializes and signs exact body", SignedXstsSerializesAndSignsExactBody);
        await Run("unsigned XSTS defaults to xboxlive RP and contract 1", UnsignedXstsDefaultsToXboxLiveRp);
        await Run("Xbox App presence RP keeps HTTPS candidate separate", XboxAppPresenceRpIsExplicit);
        await Run("unsigned XSTS carries device and title tokens", UnsignedXstsCarriesAllTokenInputs);
        await Run("presence title request uses numeric title ID and fields", PresenceTitleRequestUsesWireShape);
        await Run("numeric XErr is preserved as hexadecimal", NumericXErrIsHexadecimal);
        await Run("header X-Err is converted to hexadecimal", HeaderXErrIsHexadecimal);
        Console.WriteLine($"PASS: {_passed} offline XboxAuthNet contract tests");
        return 0;
    }

    private static async Task Run(string name, Func<Task> test)
    {
        try
        {
            await test();
            _passed++;
            Console.WriteLine($"PASS {name}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL {name}: {ex.Message}");
            throw;
        }
    }

    private static async Task SignedXstsSerializesAndSignsExactBody()
    {
        var handler = new CaptureHandler(Json("Token", "signed-result"));
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256", key = "synthetic-proof-key" });
        var request = new XboxSignedXstsRequest
        {
            UserToken = "user-token",
            DeviceToken = "device-token",
            TitleToken = "title-token",
            OptionalDisplayClaims = new[] { "xui", "xti" }
        };

        var response = await request.Send(client, signer);

        Assert(response.Token == "signed-result", "response token was not deserialized");
        Assert(handler.Request!.RequestUri!.AbsoluteUri == "https://xsts.auth.xboxlive.com/xsts/authorize", "signed URL changed");
        Assert(handler.Body == signer.Body, "signature input body differs from wire body");
        Assert(signer.RequestUri == handler.Request.RequestUri.AbsoluteUri, "signer URI differs from wire URI");
        Assert(signer.Token == string.Empty, "signed XSTS must sign an empty token field");
        using var body = JsonDocument.Parse(handler.Body!);
        var root = body.RootElement;
        Assert(root.GetProperty("RelyingParty").GetString() == "http://xboxlive.com", "signed default relying party changed");
        Assert(root.GetProperty("TokenType").GetString() == "JWT", "signed token type changed");
        var props = root.GetProperty("Properties");
        Assert(props.GetProperty("UserTokens")[0].GetString() == "user-token", "user token not forwarded");
        Assert(props.GetProperty("DeviceToken").GetString() == "device-token", "device token not forwarded");
        Assert(props.GetProperty("TitleToken").GetString() == "title-token", "title token not forwarded");
        Assert(props.GetProperty("OptionalDisplayClaims")[1].GetString() == "xti", "display claims not forwarded");
        Assert(props.GetProperty("SandboxId").GetString() == "RETAIL", "sandbox contract changed");
        Assert(!props.TryGetProperty("ProofKey", out _), "proof key must stay out of the delegated XSTS property bag");
        Assert(handler.Request.Headers.TryGetValues("Signature", out var signatures) && signatures.Single() == "synthetic-signature", "signature header missing");
        Assert(handler.Request.Headers.GetValues("x-xbl-contract-version").Single() == "1", "signed contract version must be 1");
        Assert(handler.Request.Headers.GetValues("Accept").Single() == "application/json", "common headers missing");
    }

    private static async Task UnsignedXstsDefaultsToXboxLiveRp()
    {
        var handler = new CaptureHandler(Json("Token", "unsigned-result"));
        using var client = new HttpClient(handler);
        var response = await new XboxXstsRequest { UserToken = "user-token" }.Send(client);
        Assert(response.Token == "unsigned-result", "unsigned response not deserialized");
        Assert(handler.Request!.Headers.GetValues("x-xbl-contract-version").Single() == "1", "contract version must be 1");
        using var body = JsonDocument.Parse(handler.Body!);
        Assert(body.RootElement.GetProperty("RelyingParty").GetString() == XboxAuthConstants.XboxLiveRelyingParty, "unsigned default RP changed");
        Assert(body.RootElement.GetProperty("Properties").GetProperty("UserTokens")[0].GetString() == "user-token", "unsigned user token missing");
    }

    private static Task XboxAppPresenceRpIsExplicit()
    {
        Assert(XboxAuthConstants.XboxAppRelyingParty == "https://xboxlive.com", "Xbox App RP candidate changed");
        Assert(XboxAuthConstants.XboxLiveRelyingParty == "http://xboxlive.com", "legacy RP default changed");
        return Task.CompletedTask;
    }

    private static async Task UnsignedXstsCarriesAllTokenInputs()
    {
        var handler = new CaptureHandler(Json("Token", "presence-result"));
        using var client = new HttpClient(handler);
        await new XboxXstsRequest
        {
            UserToken = "user-token",
            DeviceToken = "device-token",
            TitleToken = "title-token",
            OptionalDisplayClaims = new[] { "xui", "xti" }
        }.Send(client);
        using var body = JsonDocument.Parse(handler.Body!);
        var root = body.RootElement;
        Assert(root.GetProperty("RelyingParty").GetString() == XboxAuthConstants.XboxLiveRelyingParty, "service RP not forwarded");
        var props = root.GetProperty("Properties");
        Assert(props.GetProperty("DeviceToken").GetString() == "device-token", "device token missing");
        Assert(props.GetProperty("TitleToken").GetString() == "title-token", "title token missing");
        Assert(props.GetProperty("OptionalDisplayClaims")[0].GetString() == "xui", "display claim missing");
    }

    private static Task PresenceTitleRequestUsesWireShape()
    {
        var json = JsonSerializer.Serialize(new PresenceTitleRequest { id = 12345678 });
        using var body = JsonDocument.Parse(json);
        var root = body.RootElement;
        Assert(root.GetProperty("id").ValueKind == JsonValueKind.Number, "presence title id must be a JSON number");
        Assert(root.GetProperty("id").GetUInt32() == 12345678, "presence title id changed");
        Assert(root.GetProperty("state").GetString() == "active", "presence state changed");
        Assert(root.GetProperty("placement").GetString() == "full", "presence placement changed");
        return Task.CompletedTask;
    }

    private static async Task NumericXErrIsHexadecimal()
    {
        var handler = new CaptureHandler(HttpStatusCode.BadRequest, "{\"XErr\":2148916233,\"Message\":\"synthetic\"}");
        using var client = new HttpClient(handler);
        try
        {
            await new XboxXstsRequest { UserToken = "user-token" }.Send(client);
            throw new InvalidOperationException("request unexpectedly succeeded");
        }
        catch (XboxAuthException ex)
        {
            Assert(ex.StatusCode == 400, "status code was not retained");
            Assert(ex.Error == "8015dc09", $"numeric XErr conversion changed: {ex.Error}");
            Assert(ex.ErrorMessage == "synthetic", "error message was not retained");
        }
    }

    private static async Task HeaderXErrIsHexadecimal()
    {
        var handler = new CaptureHandler(HttpStatusCode.Forbidden, "forbidden");
        handler.ResponseHeaders.Add("X-Err", "2148916233");
        using var client = new HttpClient(handler);
        try
        {
            await new XboxXstsRequest { UserToken = "user-token" }.Send(client);
            throw new InvalidOperationException("request unexpectedly succeeded");
        }
        catch (XboxAuthException ex)
        {
            Assert(ex.StatusCode == 403, "header status code was not retained");
            Assert(ex.Error == "8015dc09", $"header XErr conversion changed: {ex.Error}");
        }
    }

    private static string Json(string property, string value) => $"{{\"{property}\":\"{value}\",\"NotAfter\":\"2999-01-01T00:00:00Z\"}}";

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class RecordingSigner : IXboxRequestSigner
    {
        public RecordingSigner(object proofKey) => ProofKey = proofKey;
        public object ProofKey { get; }
        public string? RequestUri { get; private set; }
        public string? Token { get; private set; }
        public string? Body { get; private set; }
        public string SignRequest(string reqUri, string token, string body)
        {
            RequestUri = reqUri;
            Token = token;
            Body = body;
            return "synthetic-signature";
        }
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;
        public CaptureHandler(string body) : this(HttpStatusCode.OK, body) { }
        public CaptureHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }
        public HttpRequestMessage? Request { get; private set; }
        public string? Body { get; private set; }
        public HttpResponseHeaders ResponseHeaders { get; } = new HttpResponseMessage().Headers;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content == null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            var response = new HttpResponseMessage(_status)
            {
                RequestMessage = request,
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            };
            foreach (var header in ResponseHeaders)
                response.Headers.TryAddWithoutValidation(header.Key, header.Value);
            return response;
        }
    }
}
