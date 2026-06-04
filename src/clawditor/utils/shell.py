"""Centralized subprocess wrapper. All external CLI tool calls go through here."""
from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class ToolMissingError(RuntimeError):
    pass


class ShellError(RuntimeError):
    def __init__(self, cmd: Sequence[str], returncode: int, stdout: str, stderr: str):
        super().__init__(
            f"command failed (exit {returncode}): {' '.join(shlex.quote(c) for c in cmd)}\n"
            f"--- stdout ---\n{stdout[-2000:]}\n--- stderr ---\n{stderr[-2000:]}"
        )
        self.cmd = list(cmd)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class Result:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def which(tool: str) -> str | None:
    return shutil.which(tool)


def require(tool: str) -> str:
    path = which(tool)
    if not path:
        raise ToolMissingError(f"required external tool not on PATH: {tool}")
    return path


def run(
    cmd: Sequence[str | Path],
    *,
    cwd: Path | None = None,
    timeout: int = 600,
    check: bool = True,
    input_text: str | None = None,
    env: dict | None = None,
) -> Result:
    str_cmd = [str(c) for c in cmd]
    proc = subprocess.run(
        str_cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
        env=env,
    )
    res = Result(str_cmd, proc.returncode, proc.stdout, proc.stderr)
    if check and not res.ok:
        raise ShellError(str_cmd, proc.returncode, proc.stdout, proc.stderr)
    return res
