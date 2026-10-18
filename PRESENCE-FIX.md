# OAuth presence fix

The OAuth path previously built `XAUTH` directly from SISU's
`AuthorizationToken`. SISU also returns `UserToken`, `TitleToken`, and a
device token. Profile and achievement APIs can accept the former bearer while
the presence service requires the title and sandbox identity claims carried by
the final XSTS token.

`HomeViewModel.GenerateTokens` now:

1. requires SISU `UserToken`, `TitleToken`, and `DeviceToken`;
2. calls `xsts/authorize` through `XboxSignedXstsRequest` with all three
   tokens, the ProofKey, and optional `xui`/`xti` display claims. The Xbox App
   profile now tries `RelyingParty=https://xboxlive.com` first, followed by the
   legacy `http://xboxlive.com` candidate. The HTTPS literal is observed in
   the native `GrtsAuthProvider` initialization path, but the shipped binary
   does not prove that the literal is the serialized RP, so both candidates
   remain explicitly labeled and are logged by status/XErr only;
3. uses that final XSTS token to construct `XBL3.0` and the XUID shown by the
   application.

This branch must be tested with a controlled Xbox account, a real title ID,
and the same sandbox used by the Xbox App. The test should record only HTTP
status, XErr, response headers, and non-sensitive claim presence. It must not
save or publish the bearer token.

The Xbox App's native `XboxAuthManager` also initializes through a separate
WinRT capability boundary (`RequiredUcsConsents` values `1`, `2`, `3`,
`EnablePresence`, and `EnableSpop`). This branch does not pretend to call that
private WinRT provider from a generic OAuth process; the remaining live gate
is whether the returned XSTS contains the title/sandbox claims accepted by
`userpresence`. Build on Windows with the repository's .NET 9 SDK and run the
OAuth login, profile/achievement read, presence POST, presence readback, and
presence DELETE sequence.
