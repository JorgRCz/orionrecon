"""
Wrapper para theHarvester — recolección de emails, hosts, IPs.
"""
import json
import tempfile
import os
from pathlib import Path
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.harvester")


class TheHarvester:
    NAME = "theharvester"
    TOOL = "theHarvester"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("theharvester", {})
        self.available = check_tool(self.TOOL)
        if not self.available:
            # Algunos distros lo instalan con minúscula
            self.available = check_tool("theHarvester") or check_tool("theharvester")

    def run(self, domain: str) -> dict:
        if not self.available:
            log.warning("[warning]theHarvester no encontrado.[/] Instala: pip install theHarvester")
            return {"error": "theHarvester not found", "emails": [], "hosts": [], "ips": []}

        sources = ",".join(self.cfg.get("sources", ["google", "bing", "crtsh"]))
        limit = self.cfg.get("limit", 500)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "harvest")
            cmd = [
                "theHarvester",
                "-d", domain,
                "-b", sources,
                "-l", str(limit),
                "-f", out_file,
            ]
            console.print(f"  [module]theHarvester[/] → {domain} | sources: {sources}")
            rc, stdout, stderr = run_cmd(cmd, timeout=300)

            emails, hosts, ips = set(), set(), set()

            # Parsear JSON si existe
            json_file = out_file + ".json"
            if os.path.exists(json_file):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    emails.update(data.get("emails", []))
                    hosts.update(data.get("hosts", []))
                    ips.update(data.get("ips", []))
                except Exception:
                    pass

            # Fallback: parsear stdout
            if not emails and not hosts:
                for line in stdout.splitlines():
                    line = line.strip()
                    if "@" in line and "." in line and len(line) < 100:
                        emails.add(line)
                    elif line.endswith(f".{domain}") or line == domain:
                        hosts.add(line)

            result = {
                "emails": sorted(emails),
                "hosts": sorted(hosts),
                "ips": sorted(ips),
                "sources": sources,
                "raw": stdout[:5000] if stdout else "",
            }

            console.print(
                f"  [success]✓[/] theHarvester: "
                f"[bold]{len(result['emails'])}[/] emails, "
                f"[bold]{len(result['hosts'])}[/] hosts"
            )
            return result
