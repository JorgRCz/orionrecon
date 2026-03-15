"""
Runner principal de OSINT/Recon.
Combina theHarvester, amass, subfinder, crt.sh y resolución DNS.
"""
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from .harvester import TheHarvester
from .amass import Amass
from .subfinder import Subfinder
from .crtsh import CrtSh
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage

log = get_logger("recon.osint")


def resolve_subdomain(subdomain: str, timeout: float = 3.0) -> dict | None:
    """Resuelve un subdominio, retorna IPs y CNAMEs si existe."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        ips = []
        cnames = []
        mx = []

        try:
            answers = resolver.resolve(subdomain, "A")
            ips = [r.address for r in answers]
        except Exception:
            pass

        try:
            answers = resolver.resolve(subdomain, "CNAME")
            cnames = [r.target.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        if ips or cnames:
            return {
                "host": subdomain,
                "ips": ips,
                "cnames": cnames,
                "alive": bool(ips),
            }
    except Exception:
        pass
    return None


class OSINTRunner:
    MODULE_NAME = "recon"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.harvester = TheHarvester(config)
        self.amass = Amass(config)
        self.subfinder = Subfinder(config)
        self.crtsh = CrtSh(config)
        self.max_threads = config.get("general", {}).get("max_threads", 20)

    def run(self, target: str) -> dict:
        # Extraer dominio base si se pasa URL
        domain = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
        console.rule(f"[module] RECON / OSINT → {domain} [/]")

        all_subdomains: set[str] = set()
        all_emails: set[str] = set()

        # --- Ejecutar en paralelo: crtsh + subfinder ---
        # theHarvester y amass toman más tiempo, los corremos aparte
        console.print("[info]Fase 1:[/] crt.sh + subfinder (paralelo)")
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {
                ex.submit(self.crtsh.run, domain): "crtsh",
                ex.submit(self.subfinder.run, domain): "subfinder",
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    res = fut.result()
                    all_subdomains.update(res.get("subdomains", []))
                except Exception as e:
                    log.error(f"Error en {name}: {e}")

        # --- theHarvester ---
        console.print("[info]Fase 2:[/] theHarvester")
        try:
            harv = self.harvester.run(domain)
            all_subdomains.update(harv.get("hosts", []))
            all_emails.update(harv.get("emails", []))
        except Exception as e:
            log.error(f"theHarvester error: {e}")

        # --- Amass ---
        console.print("[info]Fase 3:[/] amass (puede tardar varios minutos)")
        try:
            amass_res = self.amass.run(domain)
            all_subdomains.update(amass_res.get("subdomains", []))
        except Exception as e:
            log.error(f"amass error: {e}")

        # --- Resolución DNS masiva ---
        console.print(f"[info]Fase 4:[/] Resolviendo [bold]{len(all_subdomains)}[/] subdominios...")
        resolved = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(resolve_subdomain, s): s for s in all_subdomains}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    resolved.append(res)

        alive_hosts = [r for r in resolved if r["alive"]]

        # --- Guardar resultados ---
        result = {
            "domain": domain,
            "subdomains_total": len(all_subdomains),
            "subdomains": sorted(all_subdomains),
            "emails": sorted(all_emails),
            "resolved": resolved,
            "alive_hosts": alive_hosts,
        }
        self.storage.save_module(self.MODULE_NAME, result)

        # --- Findings ---
        for email in all_emails:
            self.storage.add_finding(
                title=f"Email encontrado: {email}",
                severity="info",
                module=self.MODULE_NAME,
                description="Email recolectado vía OSINT",
                host=domain,
                evidence=email,
                tags=["osint", "email"],
            )

        # --- Resumen ---
        console.print(f"\n[success]✓ RECON completo:[/]")
        console.print(f"  Subdominios encontrados : [bold]{len(all_subdomains)}[/]")
        console.print(f"  Hosts vivos (DNS)        : [bold]{len(alive_hosts)}[/]")
        console.print(f"  Emails                   : [bold]{len(all_emails)}[/]")

        return result
