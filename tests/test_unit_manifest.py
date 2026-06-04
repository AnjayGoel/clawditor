"""Unit tests for the manifest analyzer."""
from __future__ import annotations

from pathlib import Path

from clawditor.scan.manifest import run as run_manifest
from clawditor.config import RunContext


SAMPLE_MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.test"
          android:versionCode="42" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application
      android:label="X"
      android:allowBackup="true"
      android:debuggable="false"
      android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".Deeplinkable" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com" android:pathPrefix="/promo"/>
      </intent-filter>
    </activity>
    <receiver android:name=".ExportedReceiver" android:exported="true"/>
    <provider
      android:name=".FilesProvider"
      android:authorities="com.example.test.files"
      android:exported="false"
      android:grantUriPermissions="true"/>
  </application>
</manifest>
"""


def test_manifest_basic(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    ctx.smali_dir.mkdir(parents=True, exist_ok=True)
    (ctx.smali_dir / "AndroidManifest.xml").write_text(SAMPLE_MANIFEST)
    d = run_manifest(ctx)
    assert d["package"] == "com.example.test"
    assert d["version_code"] == "42"
    assert d["min_sdk"] == "24"
    assert d["target_sdk"] == "34"
    assert "android.permission.CAMERA" in d["permissions_requested"]
    assert d["application"]["allow_backup"] is True
    assert d["application"]["debuggable"] is False
    assert d["application"]["uses_cleartext_traffic"] is True
    assert len(d["exported_components"]["activities"]) == 2
    assert len(d["exported_components"]["receivers"]) == 1
    assert len(d["deeplinks"]) == 1
    assert d["deeplinks"][0]["schemes"] == ["https"]
    assert d["deeplinks"][0]["hosts"] == ["example.com"]
    assert d["providers"][0]["authorities"] == "com.example.test.files"
    # No Pairip in the sample manifest.
    assert d["has_pairip"] is False
    assert d["pairip_hit"] is None


PAIRIP_MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.wrapped">
  <application android:name="com.pairip.application.Application">
    <activity android:name="com.pairip.licensecheck.LicenseActivity"/>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
  </application>
</manifest>
"""


def test_manifest_detects_pairip(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    ctx.smali_dir.mkdir(parents=True, exist_ok=True)
    (ctx.smali_dir / "AndroidManifest.xml").write_text(PAIRIP_MANIFEST)
    d = run_manifest(ctx)
    assert d["has_pairip"] is True
    # We detect the application class first (it's checked before child elements).
    assert d["pairip_hit"] == "com.pairip.application.Application"


PAIRIP_ACTIVITY_ONLY_MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.wrapped2">
  <application android:name=".MyApp">
    <activity android:name="com.pairip.licensecheck.LicenseActivity"/>
  </application>
</manifest>
"""


def test_manifest_detects_pairip_activity_only(tmp_path: Path):
    ctx = RunContext("p", None, tmp_path); ctx.ensure_dirs()
    ctx.smali_dir.mkdir(parents=True, exist_ok=True)
    (ctx.smali_dir / "AndroidManifest.xml").write_text(PAIRIP_ACTIVITY_ONLY_MANIFEST)
    d = run_manifest(ctx)
    assert d["has_pairip"] is True
    assert d["pairip_hit"] == "com.pairip.licensecheck.LicenseActivity"
