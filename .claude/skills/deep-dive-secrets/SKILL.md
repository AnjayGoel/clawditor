---
name: deep-dive-secrets
description: Use when investigating secret-leak findings from an audited Android app — AWS keys, Stripe keys, Slack webhooks, JWTs, encrypted-token-store fallback keys. Triggers when the user mentions hardcoded secrets, leaked credentials, libsecretkeys.so, AES key in code, or asks "are these secrets real?".
---

# deep-dive-secrets

Investigate secret-leak findings to (a) confirm they're real, (b) determine blast radius, (c) prioritize rotation.

## Where to look

- `scan/secrets.json` — custom regex hits (AIzaSy*, JWT, AWS, OAuth, Branch, AppsFlyer)
- `scan/trufflehog.json` — provider-verified secrets (look for `"Verified": true` → CRITICAL)
- `scan/apkleaks.json` — broader regex sweep; `Generic_API_Key`, `Authorization_Basic` are mostly noise; focus on `Google_API_Key`, `Firebase`, `AWS_Access_Key_ID`, `Slack_Webhook`
- `decompiled/native/*/lib*.so.strings.txt` — strings dumps from every native lib; people stuff keys here thinking NDK = secret

## Confidence ladder

```
trufflehog "Verified": true        → REAL LIVE SECRET. Rotate today.
trufflehog known detector, unverified → likely real, just couldn't verify. Manually confirm.
AIzaSy*                            → REAL key. Test restrictions via `clawditor probe-key`.
AWS AKIA*                          → REAL access key. Test with `aws sts get-caller-identity` if you have permission.
Stripe sk_live_*                   → REAL. CRITICAL.
Branch key_live_*                  → Public client key; not a secret, but worth confirming.
Facebook fbXXX hex                 → Usually the client token (public); not the App Secret.
"Generic API Key" / "Auth Basic"   → almost always false positive.
JWT (eyJ...)                       → Often test fixtures inside SDKs. Decode payload to check.
```

## Confirming a JWT is fake-or-real

```bash
# Extract payload (assumes the value is in scan/secrets.json under "jwt")
cat scan/secrets.json | jq -r '.jwt[].value' | head -1 | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq .
```

If `iss` is a test domain (e.g. `https://example.com`), it's a test fixture. If `iss` is a real auth issuer (`https://securetoken.google.com/<real-project>`) and `exp` is recent, it's a real session token leaked.

## Native lib secrets

Always check:
```bash
grep -E 'AIzaSy|sk_live|AKIA|xox[abprs]-' decompiled/native/*/*.strings.txt
```

People love to put keys in `lib<something>.so` thinking it's "compiled". `strings` extracts them in seconds. Specifically named:
- `libsecretkeys.so`
- `libapi.so`
- `libnative-keys.so`
- `libconfig.so`

## Encrypted-token-store fallback keys

The pattern is:
1. App tries to encrypt user tokens using Android Keystore.
2. On Keystore exception (race, hardware failure, downgrade), falls back to a hardcoded key.
3. The hardcoded key is in code as `"random-looking-32-char-string"`.

Search:
```bash
grep -rPn '"[A-Za-z0-9_-]{24,40}"' decompiled/jadx/sources/ | grep -iE 'encrypt|aes|key|secret' | head
```

If found AND used as AES key material — HIGH. Because every install has the same fallback key.

## What to report

For each confirmed secret:
1. **Type + value (redacted to first 4 / last 4 chars)**.
2. **Where**: file path + line.
3. **Live?**: trufflehog verification status, or independent active probe result.
4. **Blast radius**: what the key gives access to (use `clawditor probe-key` for Google keys).
5. **Owner**: who should rotate it (usually obvious from the value's prefix).
6. **Fix**: rotate, restrict, remove from binary, store in keystore/KMS at runtime.

## Boundaries

- Don't post discovered secrets to a remote service.
- Don't authenticate to a service using a discovered secret beyond what `clawditor probe-*` already does.
- If a CRITICAL leak is found in someone else's app: tell the user; do not contact the vendor directly.
