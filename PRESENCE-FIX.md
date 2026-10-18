# OAuth presence fix

## Title binding of the state-only write (v0.1.9)

**Observation (user log, 2026-10-18 15:54, v0.1.8 build).** SISU contract 1
succeeded; the signed presence XSTS was issued for `http://xboxlive.com`
(`https://xboxlive.com` returned HTTP 400 for both claim sets, signed and
unsigned); the presence POST of `{"state":"active"}` to
`userpresence.xboxlive.com/.../devices/current/titles/current` returned
**200 OK** twice. No heartbeat line follows, because `SendHeartbeatAsync`
returned on the first presence success. Every earlier POST in the same log
(05:23-07:15) returned 400 `ArgumentError` with the `id`/`placement` body.

**Observation (source).** OAuth login uses `ClientId = XboxGameTitles.XboxAppPC`
and runs before a spoof title is chosen. `TitleClaimMatchesRequestedTitle`
returns `true` when `AutoSpoofedTitleID` is empty, so no mismatch was ever
logged. The native current-title body (`FUN_180257230`) names no title.

**Inference.** The service accepted the state-only write for the title
identity carried by the presenting XToken, i.e. the OAuth client title, not the
game XAU was asked to show. A 200 is consistent with the user still seeing no
game presence. This is an inference: the token's `xti.tid` was not logged and no
read-back was performed in that attempt.

**Change.**

1. The presence XSTS title/sandbox claim (`xti.tid`, `sbx`, public ids) is
   recorded as `HomeViewModel.PresenceTitleId` and logged.
2. `PresenceVerification.ClassifyStateOnlyWrite` returns `Bound`, `Mismatch` or
   `Unknown`. A known mismatch skips the state-only POST and falls back to the
   legacy heartbeat (which carries the title id in its body).
3. After any 2xx presence POST or heartbeat, XAU reads
   `GET userpresence.xboxlive.com/users/xuid({xuid})?level=all` (contract 3)
   and logs `requested_active` plus numeric active title ids. Only a read-back
   that lists the requested title as active counts as presence success.

**Unknown / boundary.** To make the state-only writer target a game, the
presenting XToken must carry that game's title identity. The native runtime
obtains it from the game's own title context through the provider at
`+0xf0`/slot `+0x50` (`GetTokenAndSignature`), whose concrete implementation is
not recovered. A generic OAuth client authenticates as its own client title;
this branch does not and will not synthesize another title's identity. With the
OAuth token the heartbeat path previously returned 403, so with this build the
expected OAuth outcome is: POST skipped (mismatch) -> heartbeat 403 -> no
read-back. With the Xbox App memory token the heartbeat previously returned
200; the new read-back will show whether the requested title then appears.


## SISU OAuth regression correction

The user's 2026-10-18 log records three `sisu` HTTP 400 failures at
15:36:03, 15:36:35 and 15:36:49, before the XSTS/presence stages. No XErr or
message was available. Earlier log entries completed SISU. Comparing source
profiles shows that v0.1.6 sent contract 1, while the subsequent RE probe
forced contract 2 without supplying the native TitleId context. The log does
not retain the response body or identify the exact server validation rule.

`XboxSisuAuthRequest` now defaults to `OAuthCompatibility`, restoring the
contract-1 header and exact existing OAuth body. `HomeViewModel` selects this
profile explicitly and logs its name/version. Native-only fields are rejected
locally in that profile instead of silently mixing contexts. There is no
automatic retry with another contract or account.

The RE-derived contract 2 remains available as explicit `NativeContextV2`.
It requires a decimal UInt64 TitleId before sending and canonicalizes it like
the native `%llu` writer. Session/UCS/consent/affinity continuation belongs to
this profile. These are adapter preconditions; full native context acquisition
and service acceptance remain unproven.

A separate local parser defect is also corrected: both known spellings of
`UseModernGamertag` now accept nullable JSON booleans. A malformed successful
response is reported as `invalid_response`, distinct from `http_error`, with
only the response byte count added to diagnostics. This parser change does
not explain an HTTP 400 sent by the service.

The correction restores the previous OAuth request contract. Live recovery
of this user's login, and live presence, still require a new controlled test.

The OAuth path previously built `XAUTH` directly from SISU's
`AuthorizationToken`. SISU can also return `UserToken`, `TitleToken`, and a
device token. The explicit XSTS path below is a protocol comparison probe.
Neither the display claims nor successful profile/achievement requests prove
which private context makes the Xbox App's presence request succeed.

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

The latest wire correction keeps `TitleRequest.id` as a JSON string. The
published REST contract declares this property as `String`; the previous
`UInt32` model silently changed values such as `0012345678` to `12345678`.
The local sanitized diagnostic log recorded `ArgumentError` responses from
the presence POST, so this change is a controlled body-shape probe rather than
a claim that the private Xbox App token has been reproduced. Offline contract
tests cover the exact string serialization and preserve leading zeroes.

The Xbox App's native `XboxAuthManager` also initializes through a separate
WinRT capability boundary (`RequiredUcsConsents` values `1`, `2`, `3`,
`EnablePresence`, and `EnableSpop`). This branch does not pretend to call that
private WinRT provider from a generic OAuth process; the remaining live gate
is whether the returned XSTS contains the title/sandbox claims accepted by
`userpresence`. Build on Windows with the repository's .NET 9 SDK and run the
OAuth login, profile/achievement read, presence POST, presence readback, and
presence DELETE sequence.

The direct `xgameruntime.dll` comparison adds another wire-parity probe: the
native current-title writer emits the state-only body `{"state":"active"}`.
XAU now uses that body by default; the richer `id`/`placement` model remains
available as a separate fixture. The transport exposes optional cloud/store
hint and request-signature slots, but never invents their values or treats an
unrelated XSTS signature as a presence signature.

The SISU request also exposes the native contract-2 fields `TitleId`,
`SessionId`, `UcsCheckinToken`, `UcsWebToken`, `UserPrompts`, `Flow`, and a
configurable sandbox. The response parser retains sibling `xti.tid` and `sbx`
claims so the presence path can reject a configured title mismatch. These
fields are available only in the explicit native profile; its TitleId is
required, while the remaining context is supplied by a provider when present.

## Response continuation recovered from native code

The retained REA/Ghidra evidence for `FUN_1802a4240` stores response
`X-SessionId` at operation `+0x238` and `X-Cluster-Affinity` at `+0x258`.
`FUN_1802a5960` emits a nonempty session as JSON `SessionId` and chooses a
nonempty affinity as the base for `/authorize`. The source binary SHA-256 is
`246b0b4de55f4395a78d341fd75d6d4309d16f4a5c76de9c440ea00c3a710d45`.
See the companion xal-native dossier `evidence/xgr-sisu-context-v2.json`.

`XboxSisuResponse.Context` now retains these headers. A 401 with a nonempty
JSON `WebPage` remains an error and carries context on that operation's
`XboxAuthException.SisuContext`. `ContinueFrom(context)` explicitly copies the
returned values to a subsequent request; there is no automatic browser,
consent submission or retry. The existing login UI does not yet continue the
native challenge state machine. Missing headers clear old context, and the
context is excluded from JSON and exception messages.

The adapter bounds headers to one value and 4096 characters without control
characters. It accepts affinity routing only to HTTPS port 443 on
`sisu.xboxlive.com` or a subdomain, with no path, credentials, query or fragment.
These are **local transport policies**, not recovered Windows rules; no real
cluster hostname or header value has been observed. Unsupported affinity is
retained in the response and rejected before continuing or sending secrets.
HTTP success handling, JSON parsing and native terminal X-Err behavior are
still a subset; this change does not establish full parser parity.

The UCS group is emitted only when both tokens are nonempty. Within that
group, `UserPrompts` defaults to an empty array. `RequestConsent=true` emits
`"Flow":"consent"`: native VA `0x180384918` contains `46 6c 6f 77 00`
(`Flow`), followed by the literal `consent` at `0x180384920`. The earlier
`"consent":"consent"` interpretation was incorrect and is removed. Prompt
ordering/uniqueness and the source of real UCS tokens remain to be closed.

Offline tests use synthetic values to cover response/error isolation,
continuation, exact signature inputs, rejected endpoints, absent/invalid
headers, the paired UCS gate and `Flow=consent`. Live presence remains
unresolved; no DLL completion percentage is increased by these adapter tests.
