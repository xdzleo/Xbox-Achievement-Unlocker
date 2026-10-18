using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace XboxAuthNet.XboxLive.Requests
{
    // Values for the native device-token profile recovered from xgameruntime.dll
    // (FUN_1802b9210 device info, FUN_1802a2c70 device-token body).
    public static class NativeDeviceInfo
    {
        // FUN_1802b9210 stores "Win32" and a Version built by RtlGetVersion with
        // the format "%lu.%lu.%lu" (major.minor.build).
        public static string VersionString(Version osVersion)
        {
            ArgumentNullException.ThrowIfNull(osVersion);
            return string.Create(CultureInfo.InvariantCulture,
                $"{osVersion.Major}.{osVersion.Minor}.{Math.Max(osVersion.Build, 0)}");
        }

        // The native "Id" is a value stored with the persistent device key, so it
        // is stable across logins. XAU has no such store; derive a stable GUID
        // from a per-machine value without exposing that value.
        public static string StableDeviceId(string machineSeed)
        {
            if (string.IsNullOrWhiteSpace(machineSeed))
                throw new ArgumentException("machine seed is required", nameof(machineSeed));
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes("XAU-native-device-id:" + machineSeed.Trim().ToLowerInvariant()));
            return new Guid(hash.AsSpan(0, 16)).ToString();
        }
    }
}
