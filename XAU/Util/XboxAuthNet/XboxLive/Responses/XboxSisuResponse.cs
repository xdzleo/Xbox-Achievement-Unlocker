using System.Text.Json.Serialization;

namespace XboxAuthNet.XboxLive.Responses
{
    public class XboxSisuResponse
    {
        [JsonIgnore]
        public XboxSisuContext? Context { get; internal set; }

        [JsonPropertyName("DeviceToken")]
        public string? DeviceToken { get; set; }

        [JsonPropertyName("TitleToken")]
        public XboxAuthResponse? TitleToken { get; set; }

        [JsonPropertyName("UserToken")]
        public XboxAuthResponse? UserToken { get; set; }

        [JsonPropertyName("AuthorizationToken")]
        public XboxAuthResponse? AuthorizationToken { get; set; }

        [JsonPropertyName("WebPage")]
        public string? WebPage { get; set; }

        [JsonPropertyName("Sandbox")]
        public string? Sandbox { get; set; }

        [JsonPropertyName("UseModernGamertag")]
        public bool? UseModernGamertag { get; set; }

        // Accept the older response spelling without serializing a second field.
        [JsonPropertyName("UseModernGamerTag")]
        public bool? LegacyUseModernGamertag
        {
            set => UseModernGamertag = value;
        }
    }
}
