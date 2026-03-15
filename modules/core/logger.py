import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

PENTEST_THEME = Theme({
    "info":     "bold cyan",
    "warning":  "bold yellow",
    "error":    "bold red",
    "success":  "bold green",
    "critical": "bold white on red",
    "high":     "bold red",
    "medium":   "bold yellow",
    "low":      "bold blue",
    "info_sev": "bold cyan",
    "module":   "bold magenta",
    "target":   "bold white",
    "dim":      "dim white",
})

console = Console(theme=PENTEST_THEME)


def get_logger(name: str) -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    return logging.getLogger(name)


SEV_COLORS = {
    "critical": "[critical]",
    "high":     "[high]",
    "medium":   "[medium]",
    "low":      "[low]",
    "info":     "[info_sev]",
    "none":     "[dim]",
}


def sev_badge(severity: str) -> str:
    sev = severity.lower()
    color = SEV_COLORS.get(sev, "[dim]")
    return f"{color}[{sev.upper()}][/]"
