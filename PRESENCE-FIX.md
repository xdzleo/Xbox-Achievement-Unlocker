# OAuth presence fix

The OAuth path previously built `XAUTH` directly from SISU's
`AuthorizationToken`. SISU also returns `UserToken`, `TitleToken`, and a
device token. Profile and achievement APIs can accept the former bearer while
the presence service requires the title and sandbox identity claims carried by
the final XSTS token.

`HomeViewModel.GenerateTokens` now:

1. requires SISU `UserToken`, `TitleToken`, and `DeviceToken`;
2. calls `xsts/authorize` through `XboxSignedXstsRequest` with all three
   tokens, the ProofKey, `RelyingParty=http://xboxlive.com`, and optional
   `xui`/`xti` display claims;
3. uses that final XSTS token to construct `XBL3.0` and the XUID shown by the
   application.

This branch must be tested with a controlled Xbox account, a real title ID,
and the same sandbox used by the Xbox App. The test should record only HTTP
status, XErr, response headers, and non-sensitive claim presence. It must not
save or publish the bearer token.

The current development host has no .NET SDK installed, so the WPF build was
not run here. Build on Windows with the repository's .NET 9 SDK and run the
OAuth login, profile/achievement read, presence POST, presence readback, and
presence DELETE sequence.
