# OAuth presence fix

## Observations from the live comparison (2026-10-18 17:22-17:26, v0.1.12)

All values below are from `events_debug.log` of one machine/account.

| | Xbox App token (memory) | OAuth login |
|---|---|---|
| Home "Active Device" | `Win32` | `iOS` (user screenshot) |
| presence read-back title ids | `704208617` | `328178078` |
| legacy heartbeat (string or numeric id) | 200 | 403 `Forbidden`, signed or not |
| current-title `{"state":"active"}` | 200 | 200 |
| current-title `{id,state,placement}` | 400 `ArgumentError` | 400 `ArgumentError` |
| game visible to the user | yes (user report) | no |

With identical requests the two tokens behave differently only at the legacy
heartbeat (authorization) and in which device/title the service attributes
the write to. That attributes the difference to the token's identity
(device type and title), not to the request shape. **The read-back reported
`requested_active=False` for the Xbox App token although the user saw the
game, so the read-back is not a reliable success signal**; it is kept only as
a diagnostic that now prints device type, title id, name, placement and state
(`DescribeReadback`) so `iOS`/`328178078` can be identified.

The first probe also hit HTTP 429 (per-user rate limit, ~20 requests in four
seconds), which invalidated the second token's rows. The probe now paces its
steps (default 1500 ms), waits between tokens and stops a token's run on 429,
logging `limitType/currentRequests/maxRequests/periodInSeconds`.

Bug fixed: `LoadSettings` did not copy `TitleBoundSisuExperiment` or
`PresenceProbe`, so those flags never took effect from `settings.json`
(`title_bound_experiment=False` in the log). Only the environment variables
worked.

## Headless test mode (v0.1.13)

`XAU.exe --cli [--info <ids>] [--probe <titleId>] [--title-bound] [--pace <ms>]
[--stop] [--exit]` drives the app's own login (Xbox App token, or the saved
OAuth session when `OAuthLogin` is on) and logs `CLI ...` and `Probe ...`
lines, ending with `CLI done`. `tools/xau-cli-test.ps1` wraps it. The runner
never reads, prints or accepts tokens and never enters credentials; with no
usable saved session it stops (`CLI error: not logged in`). `--info` looks up
names/devices of title ids; `--stop` sends the native-style DELETE of the
current-title presence plus the heartbeat DELETE.


## Controlled comparison probe (v0.1.12, opt-in diagnostic, OFF by default)

Three statements earlier in this document are **hypotheses, not findings**:
(1) the token read from the Xbox App carries a specific "presence permission"
claim; (2) the OAuth token necessarily carries only the Xbox App title;
(3) the difference comes exclusively from the token. The tokens are JWE
(`alg=RSA-OAEP`, `enc=A128CBC-HS256`), so no claim can be read client-side;
the only observable is the service response. Request shape, headers, device
identity and session state must be equalized before a difference can be
attributed to the token.

Changes:

- The v0.1.10 rule that skipped the state-only POST when the token title was
  known and different was removed. It rested on hypothesis (2). The binding is
  only logged (`binding=Bound|Mismatch|Unknown`); the read-back decides.
- `PresenceProbePlan` (offline-tested) is a fixed matrix with no token input:
  a read-back, then for each of four write variants (legacy heartbeat with
  string id, legacy heartbeat with numeric id as in upstream 2022,
  current-title `{"state":"active"}`, current-title `{id,state,placement}`) the
  write followed by a read-back; repeated with `Signature` when the token is
  bound to a ProofKey XAU holds. Headers are identical for every step and
  token (Authorization, `x-xbl-contract-version: 3`, Accept-Language, Accept).
- Enable with `"PresenceProbe": true` in `Documents\XAU\settings.json` or
  `XAU_PRESENCE_PROBE=1`. It runs once per (token set, title) when spoofing
  starts and logs `Probe context`, `Probe token[...]` (length, segments, x5t,
  fingerprint, signer, title claim) and one line per step (status, error code,
  numeric active title ids). It never logs bodies, tokens or signatures.

How to use: run it once with the Xbox App token (OAuth login off, Xbox App
open) and once with the OAuth login, same game, and compare the two logs
step by step. Context lines record whether the Xbox App process is running
and whether OAuth login is on, because session state is one of the
uncontrolled variables. Device identity (the device token behind each XToken)
is another candidate that this probe cannot observe and that is not excluded.


## Experiment: title-bound SISU (v0.1.11, opt-in, OFF by default)

**Observation (v0.1.10 log, 2026-10-18 16:27-16:28).** With the request
signed (`signed=True`), the presence POST returned 200, the read-back listed
neither the requested title (`requested_active=False`) nor any title of the
game, the presence XSTS carried `tid=none; sbx=none`, and the heartbeat still
returned 403.

**Observation (xgameruntime `FUN_1802078c8`, REA evidence
`ev_982be7c9...`).** XAL GameRuntime initialization takes `clientId`, a
nonzero `titleId` (else `0x89245108`) and `titleStoreHint` as init arguments;
the sandbox defaults to `RETAIL`. The title identity therefore enters the
native auth stack from the hosting title, and the native SISU contract 2
carries it as `TitleId`. A title-less OAuth login has no equivalent.

**Experiment.** Enabled by `"TitleBoundSisuExperiment": true` in
`Documents\XAU\settings.json` or the environment variable
`XAU_TITLE_BOUND_SISU=1`. Before the first presence write for a title (once
per OAuth session and title) XAU sends SISU `NativeContextV2` (contract 2)
with `AppId` = the Xbox App client, the same device token, `Sandbox=RETAIL`
and `TitleId` = the chosen title, rebuilds only the presence token from the
result and logs:

- `Title-bound SISU experiment: profile=NativeContextV2; contract=2; title_id=...`
- `Title-bound SISU response: ...; title_token_tid=...`
- `Title-bound presence token installed for title ...` (or the failure)

The normal XAUTH used for profile and achievements is not touched. Any
failure keeps the previous presence token; there is no retry with another
contract or title, and TitleId 0 is never sent.

**Unknown.** Whether the service honors a TitleId that differs from the
client's registered title is unproven. A previous contract-2 request without
TitleId returned HTTP 400; this one is untested live. Success means
`title_token_tid` equals the chosen title AND `Presence readback` reports
`requested_active=True`; anything else means the service ignored or rejected
the TitleId. The cloud hint (`x-xbl-cloud-hint`) origin is still unresolved.


## Request signature on presence calls (v0.1.10)

**Observation (Ghidra 12.1.4 via REA, xgameruntime.dll SHA-256
`246b0b4de55f4395a78d341fd75d6d4309d16f4a5c76de9c440ea00c3a710d45`).**

| Field | Native (`FUN_180256bd8` request prep, `FUN_180256198` final headers) | XAU before |
|---|---|---|
| Method/URL | POST `%s/users/xuid(%llu)/devices/current/titles/current` | same |
| `x-xbl-contract-version` | `DAT_18037bafc` = `"3"` (read from file bytes) | `3` |
| `Content-Type` | `application/json; charset=utf-8` | same |
| Body | `{"state":"active"}` (`FUN_180257230`) | same |
| `x-xbl-cloud-hint` / `x-xbl-store-hint` | always inserted from +0x118 / +0x138 | omitted (values unknown) |
| `Authorization` | provider result, added when +0x88 length != 0 | presence XAUTH |
| `Signature` | provider result, added when +0xa8 length != 0 | **never computed** |

`FUN_1802566f4` gets both values from the provider at +0xf0, vtable slot
+0x50, after checking the user at +0xe8 is signed in. Its strings name the
operation `GetTokenAndSignatureOnInactivePresence` / XAL
`GetTokenAndSignature`, which resolves the request URL through the NSAL
(`SignaturePolicies`, `SignaturePolicyIndex`, `%s/titles/current/endpoints`).

**Observation (public NSAL, `title.mgt.xboxlive.com/titles/default/endpoints`).**
`*.xboxlive.com` (which covers `userpresence` and `presence-heartbeat`) maps
to `RelyingParty http://xboxlive.com`, `SignaturePolicyIndex 0`: version 1,
ES256, `MaxBodyBytes 8192`, type `XBL`. `http://xboxlive.com` is also the
only RP for which XAU's presence XSTS succeeds.

**Change.** When the presence XSTS came from the signed XSTS request, XAU
keeps the ProofKey signer it was issued to and signs the presence POST, the
read-back GET and the heartbeat POST with it
(`XboxRequestSigner.SignServiceRequest`: method, path+query, Authorization,
body truncated to 8192). Tokens from the unsigned XSTS path or from process
memory are sent unsigned, as before, because XAU does not hold their key.
Logs now carry `signed=True|False`.

**Confidence / limits.** The header positions and the NSAL policy are
observed. The XBL v1 payload layout (Authorization value included for
service calls) follows XAU's existing auth signer and public implementations;
the XAL signer body inside this DLL was not decompiled. Cloud/store hint
values remain unknown and are not invented. Whether the service enforces the
signature for presence is decided only by a live read-back.

**Device token difference (recorded, not changed).** Native
`FUN_1802a2c70` sends an anonymous ProofOfPossession device request only
when the RPS string at +0x170/+0x180 is empty; otherwise it sends
`RpsTicket` + `SiteName` (an MSA-authenticated device). XAU always sends the
anonymous form with a random `SerialNumber`. The source of the native device
RPS ticket is not recovered.


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
