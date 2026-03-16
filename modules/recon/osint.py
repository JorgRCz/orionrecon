"""
Runner principal de OSINT/Recon.
Combina theHarvester, amass, subfinder, crt.sh, dnsx, alterx, gau, asnmap y Shodan.
"""
import csv
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from .harvester import TheHarvester
from .amass import Amass
from .subfinder import Subfinder
from .crtsh import CrtSh
from .dnsx_runner import DnsxRunner
from .alterx_runner import AlterxRunner
from .gau_runner import GauRunner
from .asnmap_runner import AsnmapRunner
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage

log = get_logger("recon.osint")


def resolve_subdomain(subdomain: str, timeout: float = 3.0) -> dict | None:
    """Resuelve un subdominio, retorna IPs y CNAMEs si existe."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        ips    = []
        cnames = []

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
                "host":   subdomain,
                "ips":    ips,
                "cnames": cnames,
                "alive":  bool(ips),
            }
    except Exception:
        pass
    return None


class OSINTRunner:
    MODULE_NAME = "recon"

    def __init__(self, config: dict, storage: Storage):
        self.config     = config
        self.storage    = storage
        self.harvester  = TheHarvester(config)
        self.amass      = Amass(config)
        self.subfinder  = Subfinder(config)
        self.crtsh      = CrtSh(config)
        self.dnsx       = DnsxRunner(config)
        self.alterx     = AlterxRunner(config)
        self.gau        = GauRunner(config)
        self.asnmap     = AsnmapRunner(config)
        self.max_threads = config.get("general", {}).get("max_threads", 20)

    def run(self, target: str) -> dict:
        # Extraer dominio base si se pasa URL
        domain = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
        console.rule(f"[module] RECON / OSINT → {domain} [/]")

        all_subdomains: set[str] = set()
        all_emails:     set[str] = set()

        # ── Fase 1: crtsh + subfinder (paralelo) ─────────────────────────────
        console.print("[info]Fase 1:[/] crt.sh + subfinder (paralelo)")
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {
                ex.submit(self.crtsh.run,      domain): "crtsh",
                ex.submit(self.subfinder.run,  domain): "subfinder",
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    res = fut.result()
                    all_subdomains.update(res.get("subdomains", []))
                except Exception as e:
                    log.error(f"Error en {name}: {e}")

        # ── Fase 2: theHarvester ─────────────────────────────────────────────
        console.print("[info]Fase 2:[/] theHarvester")
        try:
            harv = self.harvester.run(domain)
            all_subdomains.update(harv.get("hosts",  []))
            all_emails.update(harv.get("emails", []))
        except Exception as e:
            log.error(f"theHarvester error: {e}")

        # ── Fase 3: amass ────────────────────────────────────────────────────
        console.print("[info]Fase 3:[/] amass (puede tardar varios minutos)")
        try:
            amass_res = self.amass.run(domain)
            all_subdomains.update(amass_res.get("subdomains", []))
        except Exception as e:
            log.error(f"amass error: {e}")

        # ── Fase 4: alterx — permutaciones ───────────────────────────────────
        console.print("[info]Fase 4:[/] alterx — permutaciones de subdominios")
        try:
            perms = self.alterx.run(domain, list(all_subdomains))
            before = len(all_subdomains)
            all_subdomains.update(perms)
            console.print(
                f"  alterx agregó [bold]{len(all_subdomains) - before}[/] nuevas permutaciones"
            )
        except Exception as e:
            log.error(f"alterx error: {e}")

        # ── Fase 5: resolución DNS masiva ────────────────────────────────────
        console.print(
            f"[info]Fase 5:[/] Resolviendo [bold]{len(all_subdomains)}[/] subdominios..."
        )
        resolved = self._resolve_all(list(all_subdomains))
        alive_hosts = [r for r in resolved if r["alive"]]

        # ── Fase 6: GAU — URLs históricas ────────────────────────────────────
        console.print("[info]Fase 6:[/] GAU — URLs históricas")
        gau_result = {}
        try:
            gau_result = self.gau.run(domain)
        except Exception as e:
            log.error(f"gau error: {e}")

        # ── Fase 7: ASNmap — rangos IP ───────────────────────────────────────
        console.print("[info]Fase 7:[/] ASNmap — rangos IP por ASN")
        asn_result = {}
        try:
            asn_result = self.asnmap.run(domain)
        except Exception as e:
            log.error(f"asnmap error: {e}")

        # ── Fase 8: Shodan ───────────────────────────────────────────────────
        api_key = self.config.get("api_keys", {}).get("shodan", "")
        shodan_result = {}
        if api_key:
            console.print("[info]Fase 8:[/] Shodan recon")
            try:
                from .shodan_recon import ShodanRecon
                shodan = ShodanRecon(self.config, self.storage)
                shodan_result = shodan.run(domain)
            except Exception as e:
                log.error(f"Shodan error: {e}")
        else:
            console.print("[info]Fase 8:[/] Shodan — sin API key, saltando")

        # ── Guardar resultados ───────────────────────────────────────────────
        result = {
            "domain":           domain,
            "subdomains_total": len(all_subdomains),
            "subdomains":       sorted(all_subdomains),
            "emails":           sorted(all_emails),
            "resolved":         resolved,
            "alive_hosts":      alive_hosts,
            "gau":              gau_result,
            "asn":              asn_result,
            "shodan":           shodan_result,
        }
        self.storage.save_module(self.MODULE_NAME, result)
        self._export_csv(resolved, sorted(all_emails))

        # ── Findings ────────────────────────────────────────────────────────
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

        for url_entry in gau_result.get("interesting", [])[:50]:
            self.storage.add_finding(
                title=f"URL histórica interesante: {url_entry['url'][:80]}",
                severity="info",
                module=self.MODULE_NAME,
                description=f"URL descubierta en Wayback Machine/Common Crawl: {url_entry['reason']}",
                host=domain,
                url=url_entry["url"],
                evidence=url_entry["url"],
                tags=["osint", "gau", "historical-url"],
            )

        # ── Resumen ──────────────────────────────────────────────────────────
        console.print(f"\n[success]✓ RECON completo:[/]")
        console.print(f"  Subdominios encontrados  : [bold]{len(all_subdomains)}[/]")
        console.print(f"  Hosts vivos (DNS)         : [bold]{len(alive_hosts)}[/]")
        console.print(f"  Emails                    : [bold]{len(all_emails)}[/]")
        console.print(f"  URLs históricas (GAU)     : [bold]{gau_result.get('total', 0)}[/]")
        console.print(f"  CIDRs (ASN)               : [bold]{len(asn_result.get('cidrs', []))}[/]")

        return result

    def _resolve_all(self, subdomains: list[str]) -> list[dict]:
        """Resuelve todos los subdominios. Usa dnsx si está disponible."""
        # Intentar con dnsx primero
        dnsx_results = self.dnsx.run(subdomains)
        if dnsx_results is not None:
            return dnsx_results

        # Fallback: resolver Python nativo
        resolved = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(resolve_subdomain, s): s for s in subdomains}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    resolved.append(res)
        return resolved

    def _export_csv(self, resolved: list[dict], emails: list[str]):
        """Exporta hosts/IPs/CNAMEs y emails a archivos CSV en la sesión."""
        try:
            hosts_csv = self.storage.session_path / "recon_hosts.csv"
            with open(hosts_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["host", "ips", "cnames", "alive"])
                for h in resolved:
                    w.writerow([
                        h.get("host", ""),
                        "|".join(h.get("ips", [])),
                        "|".join(h.get("cnames", [])),
                        h.get("alive", False),
                    ])
            console.print(f"  [success]✓[/] CSV hosts: [bold]{hosts_csv}[/]")
        except Exception as e:
            log.error(f"Error exportando CSV de hosts: {e}")

        try:
            emails_csv = self.storage.session_path / "recon_emails.csv"
            with open(emails_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["email"])
                for email in emails:
                    w.writerow([email])
            console.print(f"  [success]✓[/] CSV emails: [bold]{emails_csv}[/]")
        except Exception as e:
            log.error(f"Error exportando CSV de emails: {e}")
