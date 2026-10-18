using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using XAU.ViewModels.Pages;
using XAU.ViewModels.Windows;

public class XboxRestAPI
{
    private readonly HttpClient _httpClient;

    private readonly HttpClient _eventBasedClient; // Dumb, but needed for events for now

    private readonly HttpClient _spooferClient;

    // User specifics
    private readonly string _xauth;
    private readonly string _requestedResponseLanguage;
    private readonly string? _cloudHint;
    private readonly string? _storeHint;
    private readonly string? _presenceSignature;

    public XboxRestAPI(string xauth, string? cloudHint = null, string? storeHint = null, string? presenceSignature = null)
    {
        _xauth = xauth;
        _cloudHint = cloudHint;
        _storeHint = storeHint;
        _presenceSignature = presenceSignature;
        _requestedResponseLanguage = HomeViewModel.Settings.RegionOverride ? "en-GB" : System.Globalization.CultureInfo.CurrentCulture.Name;
        var handler = new HttpClientHandler()
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };
        _httpClient = new HttpClient(handler);
        _spooferClient = new HttpClient(handler);

        var insecureEventsHandler = new HttpClientHandler()
        {
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
            //This is an absolutely terrible idea but the stupid fucking events API just cries about SSL errors
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _eventBasedClient = new HttpClient(insecureEventsHandler);
    }

    private void SetDefaultHeaders()
    {
        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Authorization, _xauth);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.AcceptLanguage, _requestedResponseLanguage);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.AcceptEncoding, HeaderValues.AcceptEncoding);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Accept, HeaderValues.Accept);


#if DEBUG
        Console.WriteLine("Headers in _httpClient:");
        foreach (var header in _httpClient.DefaultRequestHeaders)
        {
            if (header.Key == "Authorization") continue;
            Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
        }
#endif
    }

    private void SetDefaultSpooferHeaders()
    {
        _spooferClient.DefaultRequestHeaders.Clear();
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.Authorization, _xauth);
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.AcceptLanguage, _requestedResponseLanguage);
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.AcceptEncoding, HeaderValues.AcceptEncoding);
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.Accept, HeaderValues.Accept);

#if DEBUG
        Console.WriteLine("Headers in _spooferClient:");
        foreach (var header in _spooferClient.DefaultRequestHeaders)
        {
            if (header.Key == "Authorization") continue;
            Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
        }
#endif
    }

    private void SetPresenceHeaders()
    {
        _spooferClient.DefaultRequestHeaders.Clear();
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.Authorization, _xauth);
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion3);
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.AcceptLanguage, _requestedResponseLanguage);
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.Accept, HeaderValues.Accept);
        if (!string.IsNullOrWhiteSpace(_cloudHint))
            _spooferClient.DefaultRequestHeaders.Add(HeaderNames.CloudHint, _cloudHint);
        if (!string.IsNullOrWhiteSpace(_storeHint))
            _spooferClient.DefaultRequestHeaders.Add(HeaderNames.StoreHint, _storeHint);
        // The native provider supplies this only when a request-bound
        // signature is available. Do not synthesize one from XBL3.0.
        if (!string.IsNullOrWhiteSpace(_presenceSignature))
            _spooferClient.DefaultRequestHeaders.Add(HeaderNames.Signature, _presenceSignature);
    }

    private async Task<bool> SendPresenceAsync(string xuid, string titleId)
    {
        // Microsoft models TitleRequest.id as a JSON string. Validate that the
        // value is a decimal title id, but preserve its exact wire spelling.
        // Converting to UInt32 changed the body from id:"0123" to id:123;
        // the observed service response was ArgumentError, so preserve the
        // documented string representation for the next controlled probe.
        if (string.IsNullOrWhiteSpace(titleId) || titleId.Any(c => c < '0' || c > '9'))
            return false;
        if (string.IsNullOrWhiteSpace(_xauth))
        {
            HomeViewModel.EventsLog("Presence skipped: no presence-capable XAUTH is available");
            return false;
        }

        try
        {
            SetPresenceHeaders();
            // The native xgameruntime current-title writer serializes only
            // {"state":"active"}; the issued XToken supplies title/sandbox
            // identity. Keep the richer id/placement model as an explicit
            // fixture/profile, but match the observed native wire by default.
            var body = new PresenceStateRequest();
            var response = await _spooferClient.PostAsync(
                string.Format(InterpolatedXboxAPIUrls.PresenceUrl, xuid),
                new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, HeaderValues.Accept));
            HomeViewModel.EventsLog($"Presence POST => {(int)response.StatusCode} {response.StatusCode}; {await DescribeFailureAsync(response)}");
            return response.IsSuccessStatusCode;
        }
        catch (HttpRequestException ex)
        {
            HomeViewModel.EventsLog($"Presence POST transport failure: {ex.GetType().Name}");
            return false;
        }
    }

    private void SetDefaultEventBasedHeaders()
    {
        _eventBasedClient.DefaultRequestHeaders.Clear();
        _eventBasedClient.DefaultRequestHeaders.Add("user-agent", "MSDW");
        _eventBasedClient.DefaultRequestHeaders.Add("cache-control", "no-cache");
        _eventBasedClient.DefaultRequestHeaders.Add(HeaderNames.Accept, HeaderValues.Accept);
        _eventBasedClient.DefaultRequestHeaders.Add(HeaderNames.AcceptEncoding, HeaderValues.AcceptEncoding);
        _eventBasedClient.DefaultRequestHeaders.Add("reliability-mode", "standard");
        _eventBasedClient.DefaultRequestHeaders.Add("client-version", "EUTC-Windows-C++-no-10.0.22621.3296.amd64fre.ni_release.220506-1250-no");
        _eventBasedClient.DefaultRequestHeaders.Add("apikey", "0890af88a9ed4cc886a14f5e174a2827-9de66c5e-f867-43a8-a7b8-e0ddd481cca4-7548,95c1f21d6cb047a09e7b423c1cb2222e-9965f07b-54fa-498e-9727-9e8d24dec39e-7027");
        _eventBasedClient.DefaultRequestHeaders.Add("Client-Id", "NO_AUTH");
        _eventBasedClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.Telemetry);
        _eventBasedClient.DefaultRequestHeaders.Add(HeaderNames.Connection, "close");
        ;
        var authxtoken = Regex.Replace(_xauth, @"XBL3\.0 x=\d+;", "XBL3.0 x=-;");
        _eventBasedClient.DefaultRequestHeaders.Add("authxtoken", authxtoken);

#if DEBUG
        Console.WriteLine("Headers in _eventBasedClient:");
        foreach (var header in _eventBasedClient.DefaultRequestHeaders)
        {
            if (header.Key == "authxtoken") continue;
            Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
        }
#endif
    }

    public async Task<BasicProfile?> GetBasicProfileAsync()
    {
        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion2);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.Profile);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Connection, HeaderValues.KeepAlive);
        var response = await _httpClient.GetStringAsync(BasicXboxAPIUris.GamertagUrl);
        return JsonConvert.DeserializeObject<BasicProfile>(response);
    }

    public async Task<Profile?> GetProfileAsync(string xuid)
    {
        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion5);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.PeopleHub);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Connection, HeaderValues.KeepAlive);
        var responseString = await _httpClient.GetStringAsync(string.Format(InterpolatedXboxAPIUrls.ProfileUrl, xuid));
        return JsonConvert.DeserializeObject<Profile>(responseString);
    }

    public async Task<GameTitle?> GetGameTitleAsync(string xuid, string titleId)
    {
        if (string.IsNullOrWhiteSpace(xuid) || string.IsNullOrWhiteSpace(titleId))
        {
            // Don't send a request if we don't have the details
            return null;
        }

        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion2);
        var gameTitleRequest = new GameTitleRequest()
        {
            Pfns = null,
            TitleIds = new List<string>() { titleId }
        };

        var gameTitleHttpResponse = await _httpClient.PostAsync(string.Format(InterpolatedXboxAPIUrls.TitleUrl, xuid), new StringContent(JsonConvert.SerializeObject(gameTitleRequest), Encoding.UTF8, HeaderValues.Accept));
        var gameTitleResponse = await gameTitleHttpResponse.Content.ReadAsStringAsync();
        return JsonConvert.DeserializeObject<GameTitle>(gameTitleResponse);
    }

    public async Task<Gamepass?> GetGamepassMembershipAsync(string xuid)
    {
        if (string.IsNullOrWhiteSpace(xuid))
        {
            // Don't send a request if we don't have the details
            return null;
        }

        SetDefaultHeaders();
        var gpuHttpResponse = await _httpClient.GetAsync(string.Format(InterpolatedXboxAPIUrls.GamepassMembershipUrl, xuid));
        var gpuResponse = await gpuHttpResponse.Content.ReadAsStringAsync();
        return JsonConvert.DeserializeObject<Gamepass>(gpuResponse);
    }

    public async Task<TitlesList?> GetGamesListAsync(string xuid)
    {
        if (string.IsNullOrWhiteSpace(xuid))
        {
            // Don't send a request if we don't have the details
            return null;
        }

        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion2);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.TitleHub);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Connection, HeaderValues.KeepAlive);
        var responseString = await _httpClient.GetStringAsync(string.Format(InterpolatedXboxAPIUrls.TitlesUrl, xuid));
        return JsonConvert.DeserializeObject<TitlesList>(responseString);
    }

    public async Task<JObject?> GetGamertagProfileAsync(string gamertag)
    {
        if (string.IsNullOrWhiteSpace(gamertag))
        {
            // Don't send a request if we don't have the details
            return null;
        }

        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion2);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.Profile);

        string url = string.Format(InterpolatedXboxAPIUrls.GamertagSearch, gamertag);
        var response = await _httpClient.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var jsonResponse = await response.Content.ReadAsStringAsync();
        return JObject.Parse(jsonResponse);
    }

    public async Task<GameStatsResponse?> GetGameStatsAsync(string xuid, string titleId)
    {
        if (string.IsNullOrWhiteSpace(xuid) || string.IsNullOrWhiteSpace(titleId))
        {
            // Don't send a request if we don't have the details
            return null;
        }

        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion2);

        var stat = new GameStat()
        {
            TitleId = titleId
        };
        var gameStatsRequest = new GameStatsRequest()
        {
            Xuids = new List<string>() { xuid },
            Stats = new List<GameStat>() { stat }
        };
        var httpResponse = await _httpClient
                .PostAsync(BasicXboxAPIUris.UserStatsUrl, new StringContent(JsonConvert.SerializeObject(gameStatsRequest), Encoding.UTF8, HeaderValues.Accept));
        var response = await httpResponse.Content.ReadAsStringAsync();
        return JsonConvert.DeserializeObject<GameStatsResponse>(response);
    }

    public async Task SendHeartbeatAsync(string xuid, string spoofedTitleId)
    {
        if (string.IsNullOrWhiteSpace(xuid) || string.IsNullOrWhiteSpace(spoofedTitleId))
        {
            // Don't send a request if we don't have the details
            return;
        }
        if (string.IsNullOrWhiteSpace(_xauth))
        {
            HomeViewModel.EventsLog("Heartbeat skipped: no presence-capable XAUTH is available");
            return;
        }

        // Presence-scoped XSTS tokens are accepted by the modern endpoint;
        // keep the legacy heartbeat as a compatibility fallback.
        if (await SendPresenceAsync(xuid, spoofedTitleId))
            return;

        SetDefaultSpooferHeaders();
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion3);
        var heartbeatRequest = new HeartbeatRequest()
        {
            titles = new List<TitleRequest>()
            {
                new TitleRequest()
                {
                    id = spoofedTitleId
                }
            }
        };
        var heartbeatResponse = await _spooferClient.PostAsync(
        string.Format(InterpolatedXboxAPIUrls.HeartbeatUrl, xuid),
        new StringContent(JsonConvert.SerializeObject(heartbeatRequest), Encoding.UTF8, HeaderValues.Accept));
        HomeViewModel.EventsLog($"Heartbeat POST => {(int)heartbeatResponse.StatusCode} {heartbeatResponse.StatusCode}; {await DescribeFailureAsync(heartbeatResponse)}");
    }

    private static async Task<string> DescribeFailureAsync(HttpResponseMessage response)
    {
        var correlation = response.Headers.TryGetValues("X-XblCorrelationId", out var values)
            ? values.FirstOrDefault() ?? "none"
            : "none";

        if (response.IsSuccessStatusCode)
            return $"correlation={correlation}";

        var body = await response.Content.ReadAsStringAsync();
        var fields = new List<string>();
        var bodyMetadata = $"body_length={body.Length}; body_sha256={Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body)))[..16]}";
        try
        {
            var json = JObject.Parse(body);
            var keys = string.Join(",", json.Properties().Select(p => p.Name).OrderBy(name => name, StringComparer.Ordinal));
            foreach (var name in new[] { "XErr", "xerr", "error", "errorCode", "code", "message" })
            {
                var value = json[name]?.ToString();
                if (!string.IsNullOrWhiteSpace(value))
                    fields.Add($"{name}={value[..Math.Min(value.Length, 120)]}");
            }
            bodyMetadata += $"; body_keys={keys}";
        }
        catch
        {
            // Do not write arbitrary response bodies: they may contain tokens
            // or account data. Status and correlation ID are sufficient when
            // Xbox returns a non-JSON error.
        }

        return $"correlation={correlation}; {bodyMetadata}; {string.Join(",", fields)}";
    }

    public async Task StopHeartbeatAsync(string xuid)
    {
        if (string.IsNullOrWhiteSpace(xuid))
        {
            // Don't send a request if we don't have the details
            return;
        }

        SetDefaultSpooferHeaders();
        _spooferClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion3);
        await _spooferClient.DeleteAsync(string.Format(InterpolatedXboxAPIUrls.HeartbeatUrl, xuid));
    }

    public async Task<AchievementsResponse?> GetAchievementsForTitleAsync(string xuid, string titleId)
    {
        if (string.IsNullOrWhiteSpace(xuid) || string.IsNullOrWhiteSpace(titleId))
        {
            // Don't send a request if we don't have the details
            return null;
        }
        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion4);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.Achievements);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Connection, HeaderValues.KeepAlive);

        var httpResponse = await _httpClient.GetAsync(string.Format(InterpolatedXboxAPIUrls.QueryAchievementsUrl, xuid, titleId));
        var response = await httpResponse.Content.ReadAsStringAsync();
        var achievements = JsonConvert.DeserializeObject<AchievementsResponse>(response);
        return achievements;
    }

    public async Task<Xbox360AchievementResponse?> GetAchievementsFor360TitleAsync(string xuid, string titleId)
    {
        if (string.IsNullOrWhiteSpace(xuid) || string.IsNullOrWhiteSpace(titleId))
        {
            // Don't send a request if we don't have the details
            return null;
        }
        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion3);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.Achievements);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Connection, HeaderValues.KeepAlive);
        var httpResponse = await _httpClient.GetAsync(string.Format(InterpolatedXboxAPIUrls.QueryAchievements360Url, xuid, titleId));
        var response = await httpResponse.Content.ReadAsStringAsync();
        var achievements = JsonConvert.DeserializeObject<Xbox360AchievementResponse>(response);
        return achievements;
    }

    public async Task UnlockTitleBasedAchievementAsync(string serviceConfigId, string titleId, string xuid, string achievementId, bool useFakeSignature = false)
    {
        // only unlock the specified achievement
        await UnlockTitleBasedAchievementsAsync(serviceConfigId, titleId, xuid, new List<string>() { achievementId }, useFakeSignature);
    }

    public async Task UnlockTitleBasedAchievementsAsync(string serviceConfigId, string titleId, string xuid, List<string> achievementIds, bool useFakeSignature = false)
    {
        if (string.IsNullOrWhiteSpace(serviceConfigId) || string.IsNullOrWhiteSpace(titleId) || string.IsNullOrWhiteSpace(xuid) || achievementIds.Count == 0)
        {
            // Don't send a request if we don't have the details
            return;
        }

        SetDefaultHeaders();
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.ContractVersion, HeaderValues.ContractVersion2);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Host, Hosts.Achievements);
        _httpClient.DefaultRequestHeaders.Add(HeaderNames.Connection, HeaderValues.KeepAlive);
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "XboxServicesAPI/2021.10.20211005.0 c");

        if (useFakeSignature)
        {
            _httpClient.DefaultRequestHeaders.Add(HeaderNames.Signature, HeaderValues.Signature);
        }

        // Split the requests into 50 achievements each. Anything over 100 seems to BadRequest. TODO: look into
        // headers and see if we can send long data or w/e
        const int chunkSize = 50;
        for (int i = 0; i < achievementIds.Count; i += chunkSize)
        {
            var chunk = achievementIds.Skip(i).Take(chunkSize).ToList();

            var unlockRequest = new UnlockTitleBasedAchievementRequest
            {
                titleId = titleId,
                serviceConfigId = serviceConfigId,
                userId = xuid,
                achievements = chunk.Select(id => new AchievementsArrayEntry { id = id, percentComplete = "100" }).ToList()
            };

            var unlockBodyStr = JsonConvert.SerializeObject(unlockRequest);
            var bodyconverted = new StringContent(unlockBodyStr, Encoding.UTF8, HeaderValues.Accept);

            var response = await _httpClient.PostAsync(
                string.Format(InterpolatedXboxAPIUrls.UpdateAchievementsUrl, xuid, serviceConfigId), bodyconverted);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new HttpRequestException($"Failed to unlock achievement(s) for title {titleId} with status code {response.StatusCode}");
            }
        }
    }

    // TODO: see if we can handle the actual request body building
    public async Task UnlockEventBasedAchievement(string eventsToken, StringContent requestBody)
    {
        if (string.IsNullOrWhiteSpace(eventsToken))
        {
            // Don't send a request if we don't have the details
            return;
        }

        SetDefaultEventBasedHeaders();
        _eventBasedClient.DefaultRequestHeaders.Add("tickets", $"\"1\"=\"{eventsToken}\"");
        var response = await _eventBasedClient.PostAsync(BasicXboxAPIUris.TelemetryUrl, requestBody);
        var responseBody = await response.Content.ReadAsStringAsync();
        HomeViewModel.EventsLog($"POST {BasicXboxAPIUris.TelemetryUrl} => {(int)response.StatusCode} {response.StatusCode}");
        HomeViewModel.EventsLog($"Response: {responseBody}");
        if (!response.IsSuccessStatusCode)
        {
            HomeViewModel.EventsLog("Response headers:");
            foreach (var header in response.Headers)
                HomeViewModel.EventsLog($"  {header.Key}: {string.Join(", ", header.Value)}");
        }
    }

    public async Task<GamePassProducts?> GetTitleIdsFromGamePass(string prodId)
    {
        if (string.IsNullOrWhiteSpace(prodId))
        {
            // Don't send a request if we don't have the details
            return null;
        }

        SetDefaultHeaders();
        GamepassProductsRequest gamepassProducts = new GamepassProductsRequest()
        {
            Products = new List<string>() { prodId }
        };
        var titleIDsHttpResponse = await _httpClient.PostAsync(
                    BasicXboxAPIUris.GamepassCatalogUrl,
                    new StringContent(JsonConvert.SerializeObject(gamepassProducts)));
        var titleIDsResponse = await titleIDsHttpResponse.Content.ReadAsStringAsync();
        return JsonConvert.DeserializeObject<GamePassProducts>(titleIDsResponse);
    }
}
