using System;
using System.Net.Http;
using System.Threading.Tasks;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.Responses;

namespace XboxAuthNet.XboxLive.Requests
{
    public enum XboxDeviceAuthenticationMethod
    {
        ProofOfPossession = 0,
        DeviceRps = 1
    }

    public class XboxDeviceTokenRequest : AbstractXboxSignedAuthRequest
    {
        // DeviceRps is an explicit alternative to the legacy/NativeWin32 PoP profiles.
        // An OnlineId system ticket is not an OAuth user token or a device JWT.
        public XboxDeviceAuthenticationMethod AuthenticationMethod { get; set; }
        [System.Text.Json.Serialization.JsonIgnore]
        [System.Runtime.Serialization.IgnoreDataMember]
        public string? RpsTicket { get; set; }
        public string? Id { get; set; }
        public string? SerialNumber { get; set; }
        public string? DeviceType { get; set; }
        public string? DeviceVersion { get; set; }
        // NativeWin32 follows the xgameruntime body: AuthMethod, Id, DeviceType, Version,
        // then SerialNumber only when one is supplied, then ProofKey. The legacy
        // profile (default) keeps the previous body byte for byte.
        public bool NativeWin32Profile { get; set; }
        public string? RelyingParty { get; set; } = XboxAuthConstants.XboxAuthRelyingParty;

        protected override string RequestUrl => "https://device.auth.xboxlive.com/device/authenticate";
        protected override object BuildBody(object proofKey)
        {
            if (AuthenticationMethod == XboxDeviceAuthenticationMethod.DeviceRps)
            {
                if (NativeWin32Profile || Id != null || SerialNumber != null || DeviceType != null)
                    throw new InvalidOperationException("Device RPS does not accept anonymous device identity fields");
                if (string.IsNullOrEmpty(RpsTicket))
                    throw new InvalidOperationException("Device RPS requires a system service ticket");
                if (string.IsNullOrEmpty(RelyingParty))
                    throw new InvalidOperationException("RelyingParty was null");
                if (proofKey == null)
                    throw new InvalidOperationException("Device RPS requires a proof key");
                var properties = new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["AuthMethod"] = "RPS",
                    // Preserve the credential exactly, including any existing t=/d= prefix.
                    ["RpsTicket"] = RpsTicket,
                    ["SiteName"] = "user.auth.xboxlive.com"
                };
                if (!string.IsNullOrEmpty(DeviceVersion))
                    properties["Version"] = DeviceVersion;
                properties["ProofKey"] = proofKey;
                return new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["RelyingParty"] = RelyingParty,
                    ["TokenType"] = "JWT",
                    ["Properties"] = properties
                };
            }
            if (AuthenticationMethod != XboxDeviceAuthenticationMethod.ProofOfPossession)
                throw new InvalidOperationException("Unsupported device authentication method");
            if (RpsTicket != null)
                throw new InvalidOperationException("A system service ticket requires the Device RPS method");
            if (string.IsNullOrEmpty(DeviceType))
                throw new InvalidOperationException("DeviceType was null");
            if (string.IsNullOrEmpty(DeviceVersion))
                throw new InvalidOperationException("DeviceVersion was null");
            if (string.IsNullOrEmpty(RelyingParty))
                throw new InvalidOperationException("RelyingParty was null");

            if (NativeWin32Profile)
            {
                if (string.IsNullOrEmpty(Id))
                    throw new InvalidOperationException("Native device profile requires a stable Id");
                var properties = new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["AuthMethod"] = "ProofOfPossession",
                    ["Id"] = "{" + Id + "}",
                    ["DeviceType"] = DeviceType,
                    ["Version"] = DeviceVersion
                };
                if (!string.IsNullOrEmpty(SerialNumber))
                    properties["SerialNumber"] = "{" + SerialNumber + "}";
                properties["ProofKey"] = proofKey;
                return new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["Properties"] = properties,
                    ["RelyingParty"] = RelyingParty,
                    ["TokenType"] = "JWT"
                };
            }

            var id = this.Id ?? nextUUID();
            var serialNumber = this.SerialNumber ?? nextUUID();

            return new
            {
                Properties = new
                {
                    AuthMethod = "ProofOfPossession",
                    Id = "{" + id + "}",
                    DeviceType = DeviceType,
                    SerialNumber = "{" + serialNumber + "}",
                    Version = DeviceVersion,
                    ProofKey = proofKey
                },
                RelyingParty = RelyingParty,
                TokenType = "JWT"
            };
        }

        private string nextUUID()
        {
            return Guid.NewGuid().ToString();
        }

        public Task<XboxAuthResponse> Send(HttpClient httpClient, IXboxRequestSigner signer)
        {
            return Send<XboxAuthResponse>(httpClient, signer);
        }
    }
}
