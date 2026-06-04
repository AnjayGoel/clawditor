"""Rich-backed logger. Use `console` for user-facing output."""
from __future__ import annotations

from rich.console import Console

console = Console()


def stage(name: str) -> None:
    console.rule(f"[bold cyan]{name}[/]")


def info(msg: str) -> None:
    console.print(f"[dim]·[/] {msg}")


def ok(msg: str) -> None:
    console.print(f"[green]✓[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]![/] {msg}")


def err(msg: str) -> None:
    console.print(f"[red]✗[/] {msg}")


def finding(severity: str, msg: str) -> None:
    color = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }.get(severity.upper(), "white")
    console.print(f"  [{color}]{severity:<8}[/] {msg}")
