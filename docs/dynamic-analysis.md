# Dynamic analysis

`clawditor dynamic …` runs the target APK on a controlled rooted emulator,
intercepts its HTTPS traffic through mitmproxy, and uses Frida (via objection,
or raw Frida for Flutter) to bypass SSL pinning so the captured stream actually
decrypts. The result is a JSON capture summarizing every host the app hit, the
real Firestore collection names and Storage paths it touched, and how many
authenticated requests went out — i.e. the things the static pipeline can only
guess at.

## What this gives you over the static pipeline

| Question | Static answer | Dynamic answer |
| --- | --- | --- |
| Which Firestore collections does the app actually read? | inferred from string literals | the exact collection names from real requests |
| Which Storage object paths exist? | guessed from common prefixes (`users/`, `uploads/`, …) | real paths, including UUIDs in them |
| What does `Authorization:` look like at runtime? | not visible | the actual bearer token, plus any custom auth headers |
| Which domains does the app talk to that weren't string-grep-able? | partial (obfuscated strings hide) | all of them |
| Where does the login flow really go? | string-grep guesses | observable request sequence |

You feed those back into the static probes — e.g. point
`clawditor probe-firebase <project>` at the real Firestore collections, or
re-run `clawditor probe-storage <bucket>` with real path prefixes.

## One-time setup

```bash
./scripts/setup-dynamic.sh
```

That script (idempotent) installs:

- `mitmproxy` (via brew on macOS, pipx on Linux)
- `objection`, `frida-tools` (via pipx)
- Android SDK `emulator` + `platform-tools` + `system-images;android-34;google_apis;<arch>`
- An AVD named `clawditor-pixel7` (Pixel 7 device profile, API 34, **google_apis** image)
- The matching `frida-server` binary in `vendor/frida-server-<arch>`
- The NVISO `disable-flutter-tls-verification.js` in `vendor/scripts/`

You must also generate the mitmproxy CA cert once, by running `mitmproxy`
interactively (then `q`) — it writes `~/.mitmproxy/mitmproxy-ca-cert.cer` on
first launch. `clawditor dynamic start` will fail loudly if that file is missing.

### Why `google_apis`, not `google_apis_playstore`

The Play Store system image is signed in a way that refuses `adb root` and
`adb remount` — which is exactly what we need in order to push the mitmproxy
CA cert into `/system/etc/security/cacerts/` as a real root CA (the only way
to defeat Android-7+ user-CA distrust). The `google_apis` image is the same
GMS stack minus Play Store, and it accepts root. Picking the wrong image will
cause `clawditor dynamic start` to fail at the `adb root` step with a clear
diagnostic.

## Daily workflow

```bash
# Bring the stack up (boot AVD, install CA, start mitmweb, push+start frida-server).
uv run clawditor dynamic start

# (Optional) confirm everything is alive:
uv run clawditor dynamic status

# Per app:
uv run clawditor dynamic capture com.example.app --duration 90

# Heavy-SDK app whose AppsFlyer / Crashlytics / Facebook SDKs pin their own CAs:
uv run clawditor dynamic capture com.example.app --ignore-hosts auto

# Sideloaded app wrapped with Pairip (refuses to start past splash):
uv run clawditor dynamic capture com.example.app --bypass-pairip

# App that gates on Google Play Services version on launch:
uv run clawditor dynamic capture com.example.app --bypass-gms
# → writes data/dynamic-captures/com.example.app_<ts>/{flows.mitm, dynamic_capture.json}

# Capture alongside an existing static run:
uv run clawditor dynamic capture com.example.app --run-id com.example.app_20260523-120000

# Watch traffic live in the browser while it captures:
open http://127.0.0.1:8081

# Tear down at the end of the day:
uv run clawditor dynamic stop
```

## Fast mode

Chatty apps (livestream / short-video apps, anything with WebSocket spam)
can make the emulator and the app under test crawl under the default setup,
because `mitmweb` is also streaming every flow into its browser UI over a
websocket and the default Frida script hooks `SSLContext.init` on every
handshake. Add `--fast`:

```bash
uv run clawditor dynamic capture com.example.chatty --fast --duration 90
```

What it changes versus the default:

| Component | Default | `--fast` |
| --- | --- | --- |
| HTTPS proxy | `mitmweb` (web UI on :8081 + websocket flow streaming) | `mitmdump` (headless, only `--save-stream-file`) |
| TLS bypass script | `vendor/scripts/trust-killer.js` (incl. `SSLContext.init` hook) | `vendor/scripts/trust-killer-lite.js` (drops the `SSLContext.init` hook) |
| Frida spawn flags | spawn-and-hook (`--no-pause`) | same |

Trade-offs:

- No live web UI during capture. You can still browse the flows afterwards by
  re-opening the saved stream in mitmweb's read-only mode:
  ```bash
  mitmweb --no-server --rfile data/dynamic-captures/<pkg>_<ts>/flows.mitm
  ```
- The lite Frida script keeps `TrustManagerImpl.checkServerTrusted`,
  `okhttp3.CertificatePinner.check`, and the default `HostnameVerifier`
  replacement — which covers the vast majority of Android apps. Apps that pin
  by replacing `SSLContext` with a custom `TrustManager` (rare) may slip
  through; fall back to the default `--fast`-less run for those.

## Flutter apps

Flutter apps don't use the platform HTTP stack, so objection's
`android sslpinning disable` is a no-op against them — they pin via BoringSSL
inside `libflutter.so`. For those, add `--flutter`:

```bash
uv run clawditor dynamic capture <com.example.flutter.app> --flutter --duration 90
```

That spawns the app with raw Frida and attaches the bundled NVISO
`disable-flutter-tls.js` script instead.

## Output

```
data/dynamic-captures/<pkg>_<ts>/
├── flows.mitm             # raw mitmproxy stream (replay with `mitmproxy -r flows.mitm`)
└── dynamic_capture.json   # the summary the clawditor CLI prints + future probes consume
```

`dynamic_capture.json` shape:

```json
{
  "duration_s": 60,
  "package": "com.example.app",
  "host_count": 12,
  "hosts": ["api.foo.com", "firestore.googleapis.com", "…"],
  "endpoints": {"api.foo.com": ["/v1/login", "/v1/feed?cursor=…"]},
  "request_methods": {"GET": 47, "POST": 9},
  "response_status_counts": {"200": 41, "401": 2, "…": 13},
  "firestore": {"projects": ["foo-prod"], "collections": ["users", "shows"]},
  "storage":   {"buckets": ["foo-prod.appspot.com"], "paths_observed": ["users/123/avatar.jpg"]},
  "auth_token_count": 3,
  "jwts_in_responses": 2
}
```

## Limitations

- **Play Integrity / SafetyNet / strong root detection.** Some apps refuse to
  run when they detect a rooted/emulated device. There's no built-in defeat
  for that here — escalate to a physical device with Magisk + Shamiko +
  Zygisk-MagiskHide-Props (out of scope for this pipeline). Symptom: app
  immediately exits or refuses to log in.
- **Native pinning that objection's hooks miss.** Some apps pin in custom C++
  layers. You can drop your own Frida script as `extra_script=` (currently
  only exposed via the Python API; CLI flag is a future addition).
- **The capture is opportunistic.** It records whatever the app does during
  the time window. If you don't drive the UI, you'll only see splash-screen
  and pre-login traffic. Pass a `drive_script=` list of `adb shell input …`
  commands when you call `capture.capture()` directly to script the user
  journey, or just tap through manually during the capture window.

## Known gotchas — read this if traffic isn't flowing

These are the things that ate hours during live captures. If your `dynamic_capture.json`
has zero hosts, an obviously incomplete host set, or the app refuses to start, walk this
list before doing anything else.

1. **Android 14 APEX cacerts (the silent killer).** Pushing the mitm CA to
   `/system/etc/security/cacerts/<hash>.0` is **not enough** on Android 14.
   Apps using `com.android.conscrypt` — which is essentially every app — read
   from `/apex/com.android.conscrypt/cacerts/` instead. `clawditor dynamic start`
   bind-mounts a tmpfs there, copies all the standard system CAs in, and adds
   our mitm CA. This overlay is **lost on every reboot**: if you `adb reboot`
   outside the clawditor flow, re-run `clawditor dynamic start` (or apply the
   overlay manually with the one-liner below). Symptom of a missing overlay:
   `dynamic_capture.json` is empty even though the proxy looks correctly
   configured (`adb shell settings get global http_proxy` returns
   `10.0.2.2:8080`).
   ```bash
   # Manual one-liner if you can't or don't want to re-run dynamic start:
   adb -s emulator-5554 shell 'mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts/ \
     && cp /system/etc/security/cacerts/* /apex/com.android.conscrypt/cacerts/ \
     && chmod 644 /apex/com.android.conscrypt/cacerts/*'
   ```

2. **Chrome on Android does NOT use the system CA store.** Since Chrome 109
   it ships its own bundled CAs. Do **not** use Chrome to sanity-check that
   the proxy works — its TLS handshakes will fail even when the system CA is
   correctly installed. Use the target APK directly, or a non-Chrome browser
   (Firefox uses the system store).

3. **SDK-level cert pinning blocks the whole app.** AppsFlyer, the Facebook
   SDK, Crashlytics, GMS internals — each ships its own bundled CA set,
   ignores the system store, and ignores our `TrustManager` hooks. When these
   SDK inits fail (TLS handshake error), the app often gives up on its own
   backend calls because its SDK init chain hasn't completed. Use
   `--ignore-hosts auto` so the proxy tunnels those SDK calls through
   undecoded — the SDK is happy, the app proceeds, and we still capture
   everything we care about (the app's own backend).
   ```bash
   uv run clawditor dynamic capture com.heavy.sdk.app --ignore-hosts auto
   ```
   Use a custom regex if `auto` is too broad or too narrow for your target.

4. **Pairip license check (Play's anti-piracy framework).** Apps wrapped with
   Pairip refuse to start when sideloaded — Play license verification fails.
   Use `--bypass-pairip`. If the static scan flagged `"has_pairip": true` in
   `<run>/scan/manifest.json`, the capture command auto-warns you about this.
   ```bash
   uv run clawditor dynamic capture com.wrapped.app --bypass-pairip
   ```

5. **GMS version-check dialog ("Update Google Play services").** Blocks app
   startup when the AVD's bundled GMS is older than the app's declared
   minimum. Use `--bypass-gms`. This doesn't help if the app *actually* uses
   newer GMS APIs at runtime, but most apps only gate at startup and run fine
   once past the dialog.

6. **`frida-server` and the AVD survive reboot — but the apex CA overlay does
   not.** Don't be surprised that the device-id persists across reboots while
   captures stop working. The frida-server binary itself only needs to be
   re-pushed if it was deleted; the install survives reboots. The mitm CA
   overlay on `/apex/com.android.conscrypt/cacerts/` does not.

7. **Two ADB devices in play.** If you have a real phone connected via
   wireless ADB *and* the emulator running, always pass `-s emulator-5554` to
   every `adb` call and `-D emulator-5554` to every `frida` call. Without
   that, the wrong device gets targeted and you get cryptic errors like
   `Failed to spawn: need Gadget to attach on jailed Android`. The clawditor
   CLI already does this internally; only matters when you reach for `adb` /
   `frida` directly.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `adb root` returns "production builds" | AVD uses the Play Store image | Re-create with `system-images;android-34;google_apis;<arch>` |
| `mitmproxy CA not found at ~/.mitmproxy/…` | Never launched mitmproxy locally | Run `mitmproxy` once, press `q` to quit |
| Capture file is empty | Proxy isn't catching app traffic | Confirm `adb shell settings get global http_proxy` returns `10.0.2.2:8080`; check the app isn't bypassing system proxy via per-app NSC (`scan/network_security.json`) |
| App crashes immediately under objection | Pinning bypass conflicts with anti-tampering | Try `--flutter` (if it's Flutter), or attach manually with `frida -U -f <pkg> --no-pause` and pick a different bypass script |
| `frida-server` won't start | Binary arch mismatch | Re-run `scripts/setup-dynamic.sh` after deleting `vendor/frida-server-*`; the script detects arch from `uname -m` |
| HTTP/3 traffic missing from capture | mitmproxy can't yet MITM HTTP/3 reliably | Force the app to HTTP/2 by blocking UDP/443 on the host firewall, or accept the gap |
