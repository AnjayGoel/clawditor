"""Inspect APK assets/ for accidentally-bundled dev artifacts."""
from __future__ import annotations
import json
import zipfile
from clawditor.config import RunContext
from clawditor.utils import logging as log


# Patterns to flag (path-substring match, case-insensitive)
SUSPICIOUS_PATTERNS = [
    # Source control
    (".git/", "git_directory", "HIGH", ".git directory bundled — exposes commit history and possibly secrets"),
    (".gitignore", "gitignore", "LOW", ".gitignore bundled (not sensitive but indicates loose build)"),
    (".svn/", "svn_directory", "HIGH", "SVN metadata bundled"),

    # Env / config
    (".env", "env_file", "HIGH", ".env file in APK — usually contains secrets"),
    (".env.local", "env_file", "HIGH", ".env.local in APK"),
    (".env.production", "env_file", "HIGH", ".env.production in APK"),

    # Source maps (leak readable JS / TS source)
    (".js.map", "js_source_map", "MEDIUM", "JavaScript source map shipped — leaks original source"),
    (".css.map", "css_source_map", "LOW", "CSS source map shipped"),
    (".ts.map", "ts_source_map", "MEDIUM", "TypeScript source map shipped"),

    # Backup / archive
    (".bak", "backup_file", "MEDIUM", "Backup file shipped"),
    (".swp", "swap_file", "LOW", "Vim swap file shipped"),
    (".orig", "merge_residue", "LOW", "Merge conflict residue"),
    (".rej", "patch_reject", "LOW", "Patch reject file"),

    # IDE
    (".idea/", "intellij_config", "LOW", "IntelliJ project files shipped"),
    (".vscode/", "vscode_config", "LOW", "VSCode project files shipped"),

    # Test
    ("/test/", "test_directory", "LOW", "Test directory shipped (look for credentials)"),
    ("/__tests__/", "jest_tests", "LOW", "Jest test files shipped"),

    # Build artifacts that shouldn't ship
    ("BUILD.bazel", "build_file", "LOW", "Bazel BUILD file"),
    ("Makefile", "makefile", "INFO", "Makefile in APK"),
    (".classpath", "eclipse_classpath", "LOW", "Eclipse classpath bundled"),

    # Backup formats
    (".dump", "db_dump", "HIGH", "Database dump in APK"),
    ("backup.zip", "backup_zip", "HIGH", "backup.zip in APK"),
    ("backup.tar", "backup_tar", "HIGH", "backup.tar in APK"),

    # Database files
    (".sqlite", "sqlite_db", "MEDIUM", "Pre-populated SQLite database (may contain seed data + creds)"),
    (".db", "db_file", "LOW", "DB file (could be SQLite)"),

    # Private keys / certs (already partially covered by secrets but check filenames)
    ("id_rsa", "ssh_private_key", "CRITICAL", "SSH private key bundled"),
    (".pem", "pem_file", "LOW", "PEM file (check content; could be cert chain or actual key)"),
    (".p12", "pkcs12", "HIGH", "PKCS#12 key store"),
    (".jks", "java_keystore", "HIGH", "Java keystore"),
    (".keystore", "keystore", "HIGH", "Keystore file"),

    # AWS / cloud configs
    (".aws/credentials", "aws_credentials", "CRITICAL", "AWS credentials file"),
    ("gcloud-credentials.json", "gcloud_credentials", "CRITICAL", "GCloud credentials"),
    ("kubeconfig", "kubeconfig", "HIGH", "Kubernetes config"),
]


def run(ctx: RunContext) -> dict:
    findings = []
    try:
        with zipfile.ZipFile(ctx.universal_apk) as z:
            names = z.namelist()
    except Exception as e:
        log.warn(f"asset_inspector: couldn't open APK: {e}")
        return {}

    name_full = list(names)

    for pattern, kind, severity, description in SUSPICIOUS_PATTERNS:
        p_lower = pattern.lower()
        matches = []
        for name in name_full:
            lname = name.lower()
            if pattern.endswith("/"):
                # Directory check
                if p_lower in lname:
                    matches.append(name)
            else:
                # Suffix or basename check
                if lname.endswith(p_lower) or "/" + p_lower in lname or lname == p_lower:
                    matches.append(name)
        if matches:
            findings.append({
                "kind": kind,
                "severity": severity,
                "description": description,
                "matches": matches[:20],  # cap
                "count": len(matches),
            })

    (ctx.scan_dir / "asset_inspector.json").write_text(json.dumps({"findings": findings}, indent=2))
    log.ok(f"asset_inspector: {len(findings)} suspicious file class(es)")
    return {"findings": findings}
