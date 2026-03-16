"""
Wrapper para gau (GetAllUrls) — URLs históricas de Wayback Machine, Common Crawl, etc.
Descubre endpoints históricos que pueden revelar información sensible.
"""
import tempfile
import os
import re
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.gau")

# Extensiones de archivo interesantes para revisar
INTERESTING_EXTENSIONS = {
    ".js", ".json", ".php", ".asp", ".aspx",
    ".env", ".config", ".bak", ".sql",
    ".yaml", ".yml", ".xml", ".txt",
    ".log", ".conf", ".ini",
}

# Patrones en la URL que indican contenido potencialmente sensible
SENSITIVE_PATTERNS = [
    "api", "admin", "config", "backup", "secret",
    "token", "key", "password", "passwd", "credential",
    "auth", "login", "debug", "test", "dev", "staging",
    "internal", "private", "hidden",
]


class GauRunner:
    NAME = "gau"
    TOOL = "gau"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("gau", {})
        self.available = check_tool(self.TOOL)

    def run(self, domain: str) -> dict:
        """
        Obtiene URLs históricas del dominio (incluyendo subdominios).
        Retorna dict con todas las URLs y las marcadas como "interesantes".
        """
        if not self.available:
            log.debug("gau no disponible, saltando URLs históricas")
            return {"urls": [], "interesting": [], "total": 0}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "gau_out.txt")

            cmd = [
                "gau",
                "--subs",          # incluir subdominios
                domain,
                "--o", out_file,
            ]

            console.print(f"  [module]gau[/] → {domain}")
            rc, stdout, stderr = run_cmd(cmd, timeout=300)

            all_urls = []
            if os.path.exists(out_file):
                with open(out_file, encoding="utf-8", errors="replace") as f:
                    all_urls = [line.strip() for line in f if line.strip()]
            elif stdout:
                all_urls = [line.strip() for line in stdout.splitlines() if line.strip()]

            interesting = self._filter_interesting(all_urls)

            console.print(
                f"  [success]✓[/] gau: [bold]{len(all_urls)}[/] URLs históricas, "
                f"[bold]{len(interesting)}[/] interesantes"
            )

            return {
                "urls":       all_urls,
                "interesting": interesting,
                "total":      len(all_urls),
            }

    def _filter_interesting(self, urls: list[str]) -> list[dict]:
        """
        Filtra URLs por extensión interesante o patrón sensible.
        Los patrones se buscan SOLO en el path/query, no en el dominio,
        para evitar falsos positivos cuando el dominio contiene palabras comunes.
        """
        interesting = []
        seen = set()

        for url in urls:
            if url in seen:
                continue
            seen.add(url)

            # Separar dominio del path+query para evitar falsos positivos
            try:
                # Extraer solo el path y query string
                after_host = url.split("//", 1)[-1]  # quitar esquema
                path_and_query = after_host.split("/", 1)[-1] if "/" in after_host else ""
                path_lower = path_and_query.lower()
            except Exception:
                path_lower = url.lower()

            full_lower = url.lower()
            reasons = []

            # Comprobar extensión en la URL completa (extensiones siempre son relevantes)
            for ext in INTERESTING_EXTENSIONS:
                if ext in full_lower:
                    reasons.append(f"extensión {ext}")
                    break

            # Comprobar patrones sensibles SOLO en el path/query
            for pattern in SENSITIVE_PATTERNS:
                if pattern in path_lower:
                    reasons.append(f"patrón '{pattern}'")
                    break

            if reasons:
                interesting.append({
                    "url":    url,
                    "reason": ", ".join(reasons[:2]),
                })

        return interesting
