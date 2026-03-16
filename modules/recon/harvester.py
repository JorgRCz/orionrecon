"""
Wrapper para theHarvester — recolección de emails, hosts, IPs.
Fuentes mejoradas que no requieren API key para funcionar.
"""
import json
import re
import tempfile
import os
from pathlib import Path
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.harvester")

# Regex para extraer emails del stdout de forma agresiva
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_HOST_RE  = re.compile(r"([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}")

# Fuentes que funcionan sin API key
DEFAULT_SOURCES = [
    "crtsh", "certspotter", "hackertarget",
    "dnsdumpster", "anubis", "rapiddns",
    "yahoo", "sitedossier",
]


class TheHarvester:
    NAME = "theharvester"
    TOOL = "theHarvester"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("theharvester", {})
        self.api_keys = config.get("api_keys", {})

        # Comprobar varios nombres posibles
        self.available = (
            check_tool("theHarvester")
            or check_tool("theharvester")
        )

    def _build_sources(self) -> str:
        sources = list(self.cfg.get("sources", DEFAULT_SOURCES))

        # Agregar fuentes opcionales si hay API key
        if self.api_keys.get("shodan"):
            if "shodan" not in sources:
                sources.append("shodan")

        if self.api_keys.get("virustotal"):
            if "virustotal" not in sources:
                sources.append("virustotal")

        return ",".join(sources)

    def _parse_json_output(self, json_file: str) -> tuple[set, set, set]:
        """Parsea el archivo JSON de salida de theHarvester."""
        emails, hosts, ips = set(), set(), set()
        try:
            with open(json_file, encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            # Diferentes versiones de theHarvester tienen keys distintas
            # v4.x usa "emails", "hosts", "ips"
            # Algunas versiones usan "data" con listas
            for key in ("emails", "Emails", "email"):
                for item in data.get(key, []):
                    if isinstance(item, str):
                        emails.add(item.strip().lower())
                    elif isinstance(item, dict):
                        val = item.get("email") or item.get("value") or ""
                        if val:
                            emails.add(val.strip().lower())

            for key in ("hosts", "Hosts", "host", "subdomains"):
                for item in data.get(key, []):
                    if isinstance(item, str):
                        hosts.add(item.strip().lower())
                    elif isinstance(item, dict):
                        val = item.get("host") or item.get("value") or item.get("name") or ""
                        if val:
                            hosts.add(val.strip().lower())

            for key in ("ips", "IPs", "ip", "ip_addresses"):
                for item in data.get(key, []):
                    if isinstance(item, str):
                        ips.add(item.strip())
                    elif isinstance(item, dict):
                        val = item.get("ip") or item.get("value") or ""
                        if val:
                            ips.add(val.strip())

            # Algunos parsers guardan todo dentro de una lista "data"
            for entry in data.get("data", []):
                if isinstance(entry, str):
                    if "@" in entry:
                        emails.add(entry.strip().lower())
                    else:
                        hosts.add(entry.strip().lower())

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            log.debug(f"JSON parse parcial: {e}")
        except Exception as e:
            log.debug(f"Error leyendo JSON de theHarvester: {e}")

        return emails, hosts, ips

    def _parse_stdout_fallback(self, stdout: str, domain: str) -> tuple[set, set]:
        """Extrae emails y hosts del stdout con regex como fallback agresivo."""
        emails = set()
        hosts  = set()

        # Saltar el banner ASCII de theHarvester (líneas con '*') y
        # solo capturar emails que pertenezcan al dominio objetivo
        for line in stdout.splitlines():
            line = line.strip()
            # Ignorar líneas de banner (contienen '*') y líneas vacías
            if "*" in line or not line:
                continue
            # Buscar emails — solo los del dominio objetivo
            for m in _EMAIL_RE.finditer(line):
                email = m.group(0).lower()
                if email.endswith(f"@{domain}") or f".{domain}" in email.split("@")[-1]:
                    emails.add(email)

            # Buscar subdominios del dominio objetivo
            lower = line.lower()
            if domain in lower:
                for m in _HOST_RE.finditer(lower):
                    candidate = m.group(0).rstrip(".")
                    if candidate.endswith(f".{domain}") or candidate == domain:
                        hosts.add(candidate)

        return emails, hosts

    def run(self, domain: str) -> dict:
        if not self.available:
            log.warning("[warning]theHarvester no encontrado.[/] Instala: pip install theHarvester")
            return {"error": "theHarvester not found", "emails": [], "hosts": [], "ips": []}

        sources = self._build_sources()
        limit   = self.cfg.get("limit", 500)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "harvest")
            cmd = [
                "theHarvester",
                "-d", domain,
                "-b", sources,
                "-l", str(limit),
                "-f", out_file,
                "-n",          # DNS lookup
            ]

            console.print(f"  [module]theHarvester[/] → {domain} | sources: {sources}")
            rc, stdout, stderr = run_cmd(cmd, timeout=600)

            emails, hosts, ips = set(), set(), set()

            # 1. Parsear JSON si existe
            json_file = out_file + ".json"
            if os.path.exists(json_file):
                e, h, i = self._parse_json_output(json_file)
                emails.update(e)
                hosts.update(h)
                ips.update(i)

            # 2. Fallback: parsear stdout (siempre, no sólo cuando JSON falla)
            e2, h2 = self._parse_stdout_fallback(stdout, domain)
            emails.update(e2)
            hosts.update(h2)

            # 3. También intentar con stderr (algunas versiones imprimen ahí)
            if stderr:
                e3, h3 = self._parse_stdout_fallback(stderr, domain)
                emails.update(e3)
                hosts.update(h3)

            # Limpiar hosts: solo subdominios del dominio objetivo
            hosts = {h for h in hosts if domain in h}

            result = {
                "emails": sorted(emails),
                "hosts":  sorted(hosts),
                "ips":    sorted(ips),
                "sources": sources,
                "raw": stdout[:5000] if stdout else "",
            }

            console.print(
                f"  [success]✓[/] theHarvester: "
                f"[bold]{len(result['emails'])}[/] emails, "
                f"[bold]{len(result['hosts'])}[/] hosts"
            )
            return result
