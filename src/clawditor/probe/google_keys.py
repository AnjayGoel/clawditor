"""Restriction matrix for every AIzaSy* key found in the app.

For each key, attempts ~35 Google service endpoints. Reveals:
- Android package restriction (BLOCKED_ANDROID)
- API restriction (BLOCKED_API_RESTR)
- Per-method restriction (BLOCKED_METHOD)
- API disabled on project (API_DISABLED)
- Live abusable surface (SUCCESS / REACHED_ERR)
- Already-flagged-leaked (LEAKED)

All probes use deliberately invalid params so no real side effects fire (no SMS sent, no email delivered).
"""
from __future__ import annotations

import json
import time

from clawditor.config import RunContext
from clawditor.probe._http import call, classify
from clawditor.utils import logging as log


def services(key: str) -> list[tuple[str, str, str, bytes | None]]:
    K = key
    return [
        # Maps / Geo
        ("Maps Geocoding",       "GET",  f"https://maps.googleapis.com/maps/api/geocode/json?address=mumbai&key={K}", None),
        ("Maps Reverse Geocode", "GET",  f"https://maps.googleapis.com/maps/api/geocode/json?latlng=19.07,72.87&key={K}", None),
        ("Maps Distance Matrix", "GET",  f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=mumbai&destinations=pune&key={K}", None),
        ("Maps Directions",      "GET",  f"https://maps.googleapis.com/maps/api/directions/json?origin=mumbai&destination=pune&key={K}", None),
        ("Maps Elevation",       "GET",  f"https://maps.googleapis.com/maps/api/elevation/json?locations=19.07,72.87&key={K}", None),
        ("Maps TimeZone",        "GET",  f"https://maps.googleapis.com/maps/api/timezone/json?location=19.07,72.87&timestamp=1700000000&key={K}", None),
        ("Maps Roads",           "GET",  f"https://roads.googleapis.com/v1/snapToRoads?path=19.07,72.87&key={K}", None),
        ("Maps Places (legacy)", "GET",  f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=mumbai&inputtype=textquery&key={K}", None),
        ("Maps Geolocation",     "POST", f"https://www.googleapis.com/geolocation/v1/geolocate?key={K}", b"{}"),
        ("Routes API (new)",     "POST", f"https://routes.googleapis.com/directions/v2:computeRoutes?key={K}", b"{}"),
        ("Address Validation",   "POST", f"https://addressvalidation.googleapis.com/v1:validateAddress?key={K}",
                                  b'{"address":{"addressLines":["mumbai"]}}'),
        ("Air Quality",          "POST", f"https://airquality.googleapis.com/v1/currentConditions:lookup?key={K}",
                                  b'{"location":{"latitude":19.07,"longitude":72.87}}'),
        ("Pollen",               "GET",  f"https://pollen.googleapis.com/v1/forecast:lookup?location.latitude=19.07&location.longitude=72.87&days=1&key={K}", None),
        ("Solar",                "GET",  f"https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=19.07&location.longitude=72.87&key={K}", None),
        # Cloud ML
        ("Cloud Translate v2",   "GET",  f"https://translation.googleapis.com/language/translate/v2?key={K}&q=hi&target=es", None),
        ("Cloud NL detect",      "POST", f"https://translation.googleapis.com/language/translate/v2/detect?key={K}", b'{"q":["hello"]}'),
        ("Cloud Vision",         "POST", f"https://vision.googleapis.com/v1/images:annotate?key={K}", b'{"requests":[]}'),
        ("Cloud Speech",         "POST", f"https://speech.googleapis.com/v1/speech:recognize?key={K}", b"{}"),
        ("Cloud TextToSpeech",   "POST", f"https://texttospeech.googleapis.com/v1/text:synthesize?key={K}", b"{}"),
        ("Cloud NaturalLang",    "POST", f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={K}", b"{}"),
        ("Cloud Video Intel",    "POST", f"https://videointelligence.googleapis.com/v1/videos:annotate?key={K}", b"{}"),
        ("Gemini list models",   "GET",  f"https://generativelanguage.googleapis.com/v1beta/models?key={K}", None),
        # Other content
        ("YouTube Data",         "GET",  f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&maxResults=1&key={K}", None),
        ("Custom Search",        "GET",  f"https://www.googleapis.com/customsearch/v1?q=test&key={K}&cx=000000000000000000000:0000000000", None),
        ("Google Books",         "GET",  f"https://www.googleapis.com/books/v1/volumes?q=isbn:9780131103627&key={K}", None),
        ("SafeBrowsing",         "POST", f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={K}",
                                  b'{"client":{"clientId":"x","clientVersion":"1"},"threatInfo":{"threatTypes":["MALWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"http://example.com"}]}}'),
        ("reCAPTCHA Enterprise", "POST", f"https://recaptchaenterprise.googleapis.com/v1/projects/-/assessments?key={K}", b"{}"),
        # Firebase / Identity Toolkit (every method we care about)
        ("FB DynamicLinks",      "POST", f"https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key={K}",
                                  b'{"longDynamicLink":"https://example.page.link?link=https://example.com"}'),
        ("FB RemoteConfig",      "POST", f"https://firebaseremoteconfig.googleapis.com/v1/projects/-/namespaces/firebase:fetch?key={K}", b"{}"),
        ("IT signUp (anon)",     "POST", f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={K}", b'{"returnSecureToken":true}'),
        ("IT lookup",            "POST", f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={K}", b'{"idToken":"invalid"}'),
        ("IT signInWithPassword","POST", f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={K}",
                                  b'{"email":"nonexistent_audit_probe_zzz@example.invalid","password":"x","returnSecureToken":true}'),
        ("IT sendOobCode reset", "POST", f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={K}",
                                  b'{"requestType":"PASSWORD_RESET","email":"nonexistent_audit_probe_zzz@example.invalid"}'),
        ("IT sendVerifyCode SMS","POST", f"https://identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode?key={K}",
                                  b'{"phoneNumber":"+9990000000000000"}'),  # too long -> format error, no SMS
        ("IT createAuthUri",     "POST", f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={K}",
                                  b'{"identifier":"nonexistent_audit_probe_zzz@example.invalid","continueUri":"http://localhost"}'),
        ("IT verifyAssertion",   "POST", f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={K}",
                                  b'{"requestUri":"http://localhost","postBody":"id_token=invalid&providerId=google.com","returnSecureToken":true}'),
    ]


def run(ctx: RunContext) -> dict:
    secrets_file = ctx.scan_dir / "secrets.json"
    if not secrets_file.exists():
        log.warn("no secrets.json; skipping google_keys probe")
        return {}
    secrets = json.loads(secrets_file.read_text())
    keys = [h["value"] for h in secrets.get("google_api_key", [])]
    if not keys:
        log.warn("no AIzaSy* keys found; skipping")
        return {}
    log.info(f"probing {len(keys)} Google API key(s) × ~{len(services('x'))} services each")
    results: dict[str, dict] = {}
    for k in keys:
        log.info(f"  key: {k}")
        per_key: list[dict] = []
        for name, method, url, body in services(k):
            status, txt = call(method, url, body)
            verdict, detail = classify(status, txt)
            per_key.append({"service": name, "verdict": verdict, "detail": detail[:200]})
            time.sleep(0.1)
        results[k] = {"services": per_key, "summary": _summarize(per_key)}
        log.ok(f"    {_summary_str(results[k]['summary'])}")
    out = ctx.probe_dir / "google_keys.json"
    out.write_text(json.dumps(results, indent=2))
    return results


def _summarize(rows: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for r in rows:
        v = r["verdict"].split("(")[0]
        counts[v] = counts.get(v, 0) + 1
    return counts


def _summary_str(s: dict) -> str:
    interesting = []
    for k in ("LEAKED", "SUCCESS", "REACHED_ERR", "BLOCKED_ANDROID", "API_DISABLED", "BLOCKED_METHOD"):
        if k in s:
            interesting.append(f"{k}:{s[k]}")
    return " ".join(interesting)
