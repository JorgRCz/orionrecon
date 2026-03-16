"""
Wrapper para dnsx (ProjectDiscovery) — resolución DNS masiva.
Más rápido que Python nativo para listas grandes de hosts.
Si dnsx no está disponible retorna None (fallback a osint.py nativo).
"""
import json
import re
import tempfile
import os
from pathlib import Path
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.dnsx")

# Regex para parsear líneas: "host [ip] [cname]"
_LINE_RE = re.compile(
    r"^(?P<host>[^\s\[]+)\s+\[(?P<values>[^\]]*)\]"
)


class DnsxRunner:
    NAME = "dnsx"
    TOOL = "dnsx"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("dnsx", {})
        self.available = check_tool(self.TOOL)

    def run(self, hosts: list[str]) -> list[dict] | None:
        """
        Resuelve una lista de hosts usando dnsx.
        Retorna lista de {host, ips, cnames, alive} o None si dnsx no está.
        """
        if not self.available:
            log.debug("dnsx no disponible, usando resolver Python nativo")
            return None

        if not hosts:
            return []

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = os.path.join(tmpdir, "hosts.txt")
            out_file   = os.path.join(tmpdir, "dnsx_out.txt")

            with open(hosts_file, "w") as f:
                f.write("\n".join(hosts))

            cmd = [
                "dnsx",
                "-l", hosts_file,
                "-resp",    # mostrar respuesta
                "-a",       # registros A
                "-cname",   # registros CNAME
                "-silent",
                "-o", out_file,
            ]

            console.print(f"  [module]dnsx[/] → resolviendo {len(hosts)} hosts")
            rc, stdout, stderr = run_cmd(cmd, timeout=300)

            if not os.path.exists(out_file) and not stdout:
                log.warning("dnsx no produjo output")
                return None

            # Leer output del archivo o stdout
            content = ""
            if os.path.exists(out_file):
                with open(out_file, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            if not content and stdout:
                content = stdout

            results = []
            seen = set()
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue

                parsed = self._parse_line(line)
                if parsed and parsed["host"] not in seen:
                    seen.add(parsed["host"])
                    results.append(parsed)

            console.print(
                f"  [success]✓[/] dnsx: [bold]{len(results)}[/] hosts resueltos"
            )
            return results

    def _parse_line(self, line: str) -> dict | None:
        """
        Parsea una línea del output de dnsx.
        Formatos posibles:
          host [1.2.3.4]
          host [1.2.3.4] [cname.example.com.]
          host [ip] CNAME [target]
        """
        try:
            parts = line.split()
            if not parts:
                return None

            host = parts[0]
            ips   = []
            cnames = []

            # Extraer todos los bloques [valor]
            brackets = re.findall(r"\[([^\]]+)\]", line)
            for val in brackets:
                val = val.strip().rstrip(".")
                # Es IP si tiene el formato correcto
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                    ips.append(val)
                elif val and "." in val:
                    cnames.append(val)

            if ips or cnames:
                return {
                    "host":   host,
                    "ips":    ips,
                    "cnames": cnames,
                    "alive":  bool(ips),
                }
        except Exception as e:
            log.debug(f"Error parseando línea dnsx '{line}': {e}")
        return None
