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
        await Run("presence title request uses string title ID and fields", PresenceTitleRequestUsesWireShape);
        await Run("native presence request uses state-only body", NativePresenceStateRequestUsesWireShape);
        await Run("SISU native contract is version 2 and keeps optional fields", SisuNativeContractAndFields);
        await Run("SISU response retains operation-local continuation", SisuResponseRetainsContinuation);
        await Run("SISU challenge retains context without becoming success", SisuChallengeRetainsContext);
        await Run("SISU errors without WebPage have no continuation", SisuErrorsWithoutWebPage);
        await Run("SISU continuation clears missing fields", SisuContinuationClearsMissingFields);
        await Run("SISU affinity rejects unrelated endpoints atomically", SisuAffinityRejectsUnrelatedEndpoints);
        await Run("SISU partial UCS context and empty session are omitted", SisuPartialContextIsOmitted);
        await Run("SISU header bounds reject malformed context", SisuContextBounds);
        await Run("shared response handler keeps concurrent contexts separate", SisuConcurrentContextsAreSeparate);
        await Run("DisplayClaims retains title and sandbox siblings", DisplayClaimsRetainsTitleAndSandbox);
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
        var json = JsonSerializer.Serialize(new PresenceTitleRequest { id = "0012345678" });
        using var body = JsonDocument.Parse(json);
        var root = body.RootElement;
        Assert(root.GetProperty("id").ValueKind == JsonValueKind.String, "presence title id must be a JSON string");
        Assert(root.GetProperty("id").GetString() == "0012345678", "presence title id spelling changed");
        Assert(root.GetProperty("state").GetString() == "active", "presence state changed");
        Assert(root.GetProperty("placement").GetString() == "full", "presence placement changed");
        return Task.CompletedTask;
    }

    private static Task NativePresenceStateRequestUsesWireShape()
    {
        var json = JsonSerializer.Serialize(new PresenceStateRequest());
        using var body = JsonDocument.Parse(json);
        var root = body.RootElement;
        Assert(root.GetProperty("state").GetString() == "active", "native presence state changed");
        Assert(root.EnumerateObject().Count() == 1, "native presence body must contain only state");
        return Task.CompletedTask;
    }

    private static async Task SisuNativeContractAndFields()
    {
        var handler = new CaptureHandler(Json("Token", "sisu-result"));
        using var client = new HttpClient(handler);
        var signer = new RecordingSigner(new { alg = "ES256", key = "synthetic-proof-key" });
        await new XboxSisuAuthRequest
        {
            AccessToken = "access",
            ClientId = "XboxAppPC",
            DeviceToken = "device",
            TitleId = "704208617",
            SessionId = "session",
            UcsCheckinToken = "checkin",
            UcsWebToken = "web",
            UserPrompts = new[] { "a" },
            RequestConsent = true
        }.Send(client, signer);
        Assert(handler.Request!.Headers.GetValues("x-xbl-contract-version").Single() == "2", "SISU native contract must be 2");
        using var body = JsonDocument.Parse(handler.Body!);
        var root = body.RootElement;
        Assert(root.GetProperty("TitleId").GetString() == "704208617", "SISU title id missing");
        Assert(root.GetProperty("SessionId").GetString() == "session", "SISU session id missing");
        Assert(root.GetProperty("UcsCheckinToken").GetString() == "checkin", "SISU UCS checkin missing");
        Assert(root.GetProperty("UcsWebToken").GetString() == "web", "SISU UCS web token missing");
        Assert(root.GetProperty("Flow").GetString() == "consent", "SISU Flow=consent missing");
        Assert(!root.TryGetProperty("consent", out _), "consent is a value, not the native JSON key");
    }

    private static HttpResponseMessage SisuResponse(HttpStatusCode status, string body,
        string? session = "synthetic-session", string? cluster = "https://cluster.sisu.xboxlive.com")
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };
        if (session != null) response.Headers.TryAddWithoutValidation("x-sessionid", session);
        if (cluster != null) response.Headers.TryAddWithoutValidation("X-Cluster-Affinity", cluster);
        return response;
    }

    private static async Task SisuResponseRetainsContinuation()
    {
        using var response = SisuResponse(HttpStatusCode.OK, "{\"UserToken\":{\"Token\":\"u\"},\"TitleToken\":{\"Token\":\"t\"}}");
        var result = await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
        Assert(result.Context?.SessionId == "synthetic-session", "session header discarded");
        Assert(result.Context?.ClusterAffinity == "https://cluster.sisu.xboxlive.com", "affinity header discarded");
        Assert(!JsonSerializer.Serialize(result).Contains("synthetic-session"), "continuation leaked into response JSON");
        var request = new XboxSisuAuthRequest { AccessToken = "access" };
        request.ContinueFrom(result.Context!);
        var transport = new CaptureHandler("{}");
        using var client = new HttpClient(transport);
        var signer = new RecordingSigner(new { alg = "ES256" });
        await request.Send(client, signer);
        Assert(transport.Request!.RequestUri!.AbsoluteUri == "https://cluster.sisu.xboxlive.com/authorize", "affinity not used");
        Assert(signer.RequestUri == transport.Request.RequestUri.AbsoluteUri, "signature URL differs from destination");
        Assert(signer.Body == transport.Body, "signature body differs from wire body");
        using var json = JsonDocument.Parse(transport.Body!);
        Assert(json.RootElement.GetProperty("SessionId").GetString() == "synthetic-session", "continuation body lost session");
        Assert(!json.RootElement.TryGetProperty("ClusterAffinity", out _), "routing context entered body");
    }

    private static async Task SisuChallengeRetainsContext()
    {
        using var response = SisuResponse(HttpStatusCode.Unauthorized, "{\"WebPage\":\"https://example.invalid/consent\"}");
        try
        {
            await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
            throw new InvalidOperationException("401 challenge became success");
        }
        catch (XboxAuthException error)
        {
            Assert(error.StatusCode == 401, "challenge status discarded");
            Assert(error.SisuContext?.SessionId == "synthetic-session", "challenge lost operation context");
            Assert(!error.Message.Contains("synthetic-session"), "context entered error message");
        }
    }

    private static async Task SisuErrorsWithoutWebPage()
    {
        foreach (var item in new[] {
            (HttpStatusCode.Unauthorized, "{}"),
            (HttpStatusCode.Unauthorized, "{\"WebPage\":\"\"}"),
            (HttpStatusCode.Unauthorized, "{\"WebPage\":42}"),
            (HttpStatusCode.Forbidden, "{\"WebPage\":\"page\"}"),
            (HttpStatusCode.Unauthorized, "not-json") })
        {
            using var response = SisuResponse(item.Item1, item.Item2);
            try
            {
                await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response);
                throw new InvalidOperationException("error became success");
            }
            catch (XboxAuthException error)
            {
                Assert(error.StatusCode == (int)item.Item1, "HTTP error status changed");
                Assert(error.SisuContext == null, "nonchallenge captured continuation");
            }
        }
    }

    private static async Task SisuContinuationClearsMissingFields()
    {
        using var first = SisuResponse(HttpStatusCode.OK, "{}");
        using var empty = SisuResponse(HttpStatusCode.OK, "{}", null, null);
        var parser = new XboxAuthResponseHandler();
        var request = new XboxSisuAuthRequest { AccessToken = "access" };
        request.ContinueFrom((await parser.HandleResponse<XboxSisuResponse>(first)).Context!);
        request.ContinueFrom((await parser.HandleResponse<XboxSisuResponse>(empty)).Context!);
        Assert(request.SessionId == null && request.ClusterAffinity == null, "missing response fields reused old context");
        var transport = new CaptureHandler("{}");
        using var client = new HttpClient(transport);
        await request.Send(client, new RecordingSigner(new { alg = "ES256" }));
        Assert(transport.Request!.RequestUri!.Host == "sisu.xboxlive.com", "missing affinity did not restore default route");
        using var body = JsonDocument.Parse(transport.Body!);
        Assert(!body.RootElement.TryGetProperty("SessionId", out _), "missing session serialized");
    }

    private static async Task SisuAffinityRejectsUnrelatedEndpoints()
    {
        foreach (var endpoint in new[] { "https://example.invalid", "http://sisu.xboxlive.com",
            "https://sisu.xboxlive.com.example.invalid", "https://sisu.xboxlive.com:444",
            "https://user@sisu.xboxlive.com", "https://sisu.xboxlive.com/path",
            "https://sisu.xboxlive.com/?q=1", "https://sisu.xboxlive.com/#fragment" })
        {
            using var response = SisuResponse(HttpStatusCode.OK, "{}", "new-session", endpoint);
            var context = (await new XboxAuthResponseHandler().HandleResponse<XboxSisuResponse>(response)).Context!;
            var request = new XboxSisuAuthRequest { SessionId = "old-session" };
            try
            {
                request.ContinueFrom(context);
                throw new Exception("unrelated endpoint accepted");
            }
            catch (InvalidOperationException)
            {
                Assert(request.SessionId == "old-session" && request.ClusterAffinity == null, "rejected continuation partly mutated request");
            }
        }
    }

    private static async Task SisuPartialContextIsOmitted()
    {
        foreach (var item in new[] { ("checkin", (string?)null), ((string?)null, "web"), ("", "web") })
        {
            var transport = new CaptureHandler("{}");
            using var client = new HttpClient(transport);
            await new XboxSisuAuthRequest {
                AccessToken = "access", SessionId = "", UcsCheckinToken = item.Item1,
                UcsWebToken = item.Item2, UserPrompts = new[] { "prompt" }, RequestConsent = true
            }.Send(client, new RecordingSigner(new { alg = "ES256" }));
            using var body = JsonDocument.Parse(transport.Body!);
            foreach (var key in new[] { "SessionId", "UcsCheckinToken", "UcsWebToken", "UserPrompts", "Flow" })
                Assert(!body.RootElement.TryGetProperty(key, out _), "partial context emitted " + key);
        }
        var paired = new CaptureHandler("{}");
        using var pairedClient = new HttpClient(paired);
        await new XboxSisuAuthRequest { AccessToken = "access", UcsCheckinToken = "c", UcsWebToken = "w" }
            .Send(pairedClient, new RecordingSigner(new { alg = "ES256" }));
        using var pairedBody = JsonDocument.Parse(paired.Body!);
        Assert(pairedBody.RootElement.GetProperty("UserPrompts").GetArrayLength() == 0, "paired context requires prompts array");
        Assert(!pairedBody.RootElement.TryGetProperty("Flow", out _), "consent flow invented without request");
    }

    private static Task SisuContextBounds()
    {
        foreach (var values in new[] { new[] { "a", "b" }, new[] { new string('x', 4097) }, new[] { "a\tb" } })
        {
            using var response = SisuResponse(HttpStatusCode.OK, "{}", null, null);
            response.Headers.TryAddWithoutValidation("X-SessionId", values);
            try
            {
                XboxSisuContext.FromHeaders(response.Headers);
                throw new InvalidOperationException("invalid context accepted");
            }
            catch (JsonException error)
            {
                Assert(error.Message == "Invalid SISU X-SessionId header", "invalid context appeared in error message");
            }
        }
        return Task.CompletedTask;
    }

    private static async Task SisuConcurrentContextsAreSeparate()
    {
        var parser = new XboxAuthResponseHandler();
        async Task<XboxSisuContext?> Parse(string id)
        {
            using var response = SisuResponse(HttpStatusCode.Unauthorized, "{\"WebPage\":\"page\"}", id);
            response.Content = new YieldingContent("{\"WebPage\":\"page\"}");
            try { await parser.HandleResponse<XboxSisuResponse>(response); }
            catch (XboxAuthException error) { return error.SisuContext; }
            throw new InvalidOperationException("challenge became success");
        }
        var results = await Task.WhenAll(Parse("session-a"), Parse("session-b"));
        Assert(results[0]?.SessionId == "session-a" && results[1]?.SessionId == "session-b", "operation contexts mixed");
    }

    private static Task DisplayClaimsRetainsTitleAndSandbox()
    {
        var response = JsonSerializer.Deserialize<XboxAuthResponse>(
            "{\"DisplayClaims\":{\"xui\":[{\"uhs\":\"u\"}],\"xti\":{\"tid\":\"704208617\"},\"sbx\":\"RETAIL\"},\"Token\":\"t\",\"NotAfter\":\"2999-01-01T00:00:00Z\"}");
        Assert(response?.XuiClaims?.TitleId == "704208617", "xti.tid was discarded");
        Assert(response?.XuiClaims?.Sandbox == "RETAIL", "sbx was discarded");
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

    private sealed class YieldingContent : HttpContent
    {
        private readonly byte[] _bytes;
        public YieldingContent(string value) => _bytes = Encoding.UTF8.GetBytes(value);
        protected override bool TryComputeLength(out long length) { length = _bytes.Length; return true; }
        protected override async Task SerializeToStreamAsync(System.IO.Stream stream, TransportContext? context)
        {
            await Task.Yield();
            await stream.WriteAsync(_bytes);
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
