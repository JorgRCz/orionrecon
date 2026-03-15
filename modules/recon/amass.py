"""
Wrapper para Amass — enumeración de subdominios.
"""
import tempfile
import os
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.amass")


class Amass:
    NAME = "amass"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("amass", {})
        self.available = check_tool("amass")

    def run(self, domain: str) -> dict:
        if not self.available:
            log.warning("[warning]amass no encontrado.[/] Instala: go install github.com/owasp-amass/amass/v4/...@master")
            return {"error": "amass not found", "subdomains": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "amass_out.txt")
            timeout = self.cfg.get("timeout", 300)
            passive = self.cfg.get("passive", True)

            cmd = ["amass", "enum", "-d", domain, "-o", out_file]
            if passive:
                cmd.append("-passive")

            console.print(f"  [module]amass[/] → {domain} ({'passive' if passive else 'active'})")
            rc, stdout, stderr = run_cmd(cmd, timeout=timeout)

            subdomains = set()
            if os.path.exists(out_file):
                with open(out_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and (line.endswith(f".{domain}") or line == domain):
                            subdomains.add(line)

            # Fallback stdout
            for line in stdout.splitlines():
                line = line.strip()
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line)

            result = {"subdomains": sorted(subdomains)}
            console.print(
                f"  [success]✓[/] amass: [bold]{len(result['subdomains'])}[/] subdominios"
            )
            return result
