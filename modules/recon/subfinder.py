"""
Wrapper para subfinder — rápida enumeración pasiva de subdominios.
"""
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.subfinder")


class Subfinder:
    NAME = "subfinder"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("subfinder", {})
        self.available = check_tool("subfinder")

    def run(self, domain: str) -> dict:
        if not self.available:
            log.warning("[warning]subfinder no encontrado.[/] Instala: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return {"error": "subfinder not found", "subdomains": []}

        timeout = self.cfg.get("timeout", 120)
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]

        console.print(f"  [module]subfinder[/] → {domain}")
        rc, stdout, stderr = run_cmd(cmd, timeout=timeout)

        subdomains = set()
        for line in stdout.splitlines():
            line = line.strip()
            if line and (line.endswith(f".{domain}") or line == domain):
                subdomains.add(line)

        result = {"subdomains": sorted(subdomains)}
        console.print(
            f"  [success]✓[/] subfinder: [bold]{len(result['subdomains'])}[/] subdominios"
        )
        return result
