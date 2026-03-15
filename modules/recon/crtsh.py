"""
Enumera subdominios vía Certificate Transparency (crt.sh).
No requiere herramientas externas.
"""
import requests
from modules.core.logger import console, get_logger

log = get_logger("recon.crtsh")


class CrtSh:
    NAME = "crtsh"
    URL = "https://crt.sh/?q=%.{domain}&output=json"

    def __init__(self, config: dict):
        self.timeout = config.get("general", {}).get("timeout", 30)

    def run(self, domain: str) -> dict:
        console.print(f"  [module]crt.sh[/] → {domain}")
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=self.timeout, headers={
                "User-Agent": "PentestFramework/1.0"
            })
            resp.raise_for_status()
            data = resp.json()

            for entry in data:
                names = entry.get("name_value", "")
                for name in names.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and (name.endswith(f".{domain}") or name == domain):
                        subdomains.add(name)

        except requests.RequestException as e:
            log.warning(f"[warning]crt.sh error:[/] {e}")
        except Exception as e:
            log.error(f"crt.sh parse error: {e}")

        result = {"subdomains": sorted(subdomains)}
        console.print(
            f"  [success]✓[/] crt.sh: [bold]{len(result['subdomains'])}[/] subdominios"
        )
        return result
