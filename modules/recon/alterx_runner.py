"""
Wrapper para alterx (ProjectDiscovery) — generación de permutaciones de subdominios.
Genera posibles subdominios adicionales basados en los ya descubiertos.
"""
import tempfile
import os
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.alterx")


class AlterxRunner:
    NAME = "alterx"
    TOOL = "alterx"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("alterx", {})
        self.available = check_tool(self.TOOL)

    def run(self, domain: str, subdomains: list[str] | None = None) -> list[str]:
        """
        Genera permutaciones de subdominios.
        Si se provee una lista de subdominios, los usa como base.
        De lo contrario solo usa el dominio raíz.

        Retorna lista de posibles subdominios adicionales.
        """
        if not self.available:
            log.debug("alterx no disponible, saltando permutaciones")
            return []

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "alterx_out.txt")

            if subdomains and len(subdomains) > 0:
                # Usar lista de subdominios como input
                input_file = os.path.join(tmpdir, "subs.txt")
                with open(input_file, "w") as f:
                    f.write("\n".join(subdomains[:500]))  # limitar para no sobrecargar

                cmd = f"cat {input_file} | alterx -silent"
                rc, stdout, stderr = run_cmd(cmd, timeout=120)
            else:
                # Solo el dominio raíz
                cmd = f'echo "{domain}" | alterx -silent'
                rc, stdout, stderr = run_cmd(cmd, timeout=60)

            if rc != 0 or not stdout:
                if stderr:
                    log.debug(f"alterx stderr: {stderr[:500]}")
                return []

            results = []
            seen = set(subdomains or [])
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line and line.endswith(f".{domain}") or line == domain:
                    if line not in seen:
                        results.append(line)
                        seen.add(line)

            # Deduplicar y ordenar
            results = sorted(set(results))

            console.print(
                f"  [success]✓[/] alterx: [bold]{len(results)}[/] permutaciones generadas"
            )
            return results
