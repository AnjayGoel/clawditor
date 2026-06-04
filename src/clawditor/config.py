"""RunContext — passed through the pipeline so modules know where to read/write."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from clawditor.utils.paths import default_runs_dir


@dataclass
class RunContext:
    package: str | None
    apk_input: Path | None  # what the user passed via --apk, may be a split set or a single
    out_dir: Path
    no_probe: bool = False
    quick: bool = False
    no_jadx: bool = False
    probe_only: bool = False
    started_at: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d-%H%M%S"))

    @property
    def apk_dir(self) -> Path: return self.out_dir / "apk"
    @property
    def decompiled_dir(self) -> Path: return self.out_dir / "decompiled"
    @property
    def jadx_dir(self) -> Path: return self.decompiled_dir / "jadx"
    @property
    def smali_dir(self) -> Path: return self.decompiled_dir / "smali"
    @property
    def hermes_dir(self) -> Path: return self.decompiled_dir / "hermes"
    @property
    def native_dir(self) -> Path: return self.decompiled_dir / "native"
    @property
    def scan_dir(self) -> Path: return self.out_dir / "scan"
    @property
    def probe_dir(self) -> Path: return self.out_dir / "probe"
    @property
    def reports_dir(self) -> Path: return self.out_dir / "reports"
    @property
    def universal_apk(self) -> Path: return self.apk_dir / "universal.apk"
    @property
    def manifest_xml(self) -> Path: return self.smali_dir / "AndroidManifest.xml"

    def ensure_dirs(self) -> None:
        for d in (self.apk_dir, self.decompiled_dir, self.scan_dir, self.probe_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def for_run(cls, *, package: str | None, apk: Path | None, out: Path | None, **flags) -> "RunContext":
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        if out is None:
            slug = package or (apk.stem if apk else "run")
            out = default_runs_dir() / f"{slug}_{ts}"
        ctx = cls(package=package, apk_input=apk, out_dir=out.resolve(), started_at=ts, **flags)
        ctx.ensure_dirs()
        return ctx

    def write_meta(self) -> None:
        meta = {
            "package": self.package,
            "apk_input": str(self.apk_input) if self.apk_input else None,
            "started_at": self.started_at,
            "flags": {k: getattr(self, k) for k in ("no_probe", "quick", "no_jadx", "probe_only")},
        }
        (self.out_dir / "run.json").write_text(json.dumps(meta, indent=2))
