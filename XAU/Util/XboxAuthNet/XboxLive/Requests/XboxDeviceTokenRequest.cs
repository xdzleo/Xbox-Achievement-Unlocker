using System;
using System.Net.Http;
using System.Threading.Tasks;
using XboxAuthNet.XboxLive.Crypto;
using XboxAuthNet.XboxLive.Responses;

namespace XboxAuthNet.XboxLive.Requests
{
    public class XboxDeviceTokenRequest : AbstractXboxSignedAuthRequest
    {
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