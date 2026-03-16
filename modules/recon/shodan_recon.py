"""
Integración con Shodan API — descubrimiento de puertos, banners y vulnerabilidades
asociados al dominio objetivo.
"""
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("recon.shodan")


class ShodanRecon:
    MODULE_NAME = "shodan_recon"

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.api_key = config.get("api_keys", {}).get("shodan", "")

    def run(self, domain: str) -> dict:
        """
        Consulta Shodan para el dominio dado.
        Extrae puertos, banners, vulns, organización.
        Retorna dict vacío si no hay API key.
        """
        if not self.api_key:
            log.debug("Shodan API key no configurada, saltando")
            return {"hosts": [], "total": 0, "skipped": True}

        try:
            import shodan as shodan_lib
        except ImportError:
            log.warning("Librería shodan no instalada. Ejecuta: pip install shodan")
            return {"hosts": [], "total": 0, "skipped": True}

        console.print(f"  [module]Shodan[/] → {domain}")

        api = shodan_lib.Shodan(self.api_key)
        hosts_data = []
        findings   = []

        try:
            # Buscar por hostname
            result = api.search(f"hostname:{domain}")
            matches = result.get("matches", [])
            console.print(f"  Shodan: [bold]{len(matches)}[/] servicios encontrados")

            for match in matches:
                host_entry = self._parse_match(match, domain)
                if host_entry:
                    hosts_data.append(host_entry)

                    # Generar findings para vulnerabilidades
                    for vuln in host_entry.get("vulns", []):
                        findings.append({
                            "title": f"Shodan: {vuln} en {host_entry['ip']}:{host_entry['port']}",
                            "severity": "high",
                            "description": (
                                f"Vulnerabilidad {vuln} detectada por Shodan en "
                                f"{host_entry['ip']} puerto {host_entry['port']}"
                            ),
                            "host": host_entry["ip"],
                            "evidence": host_entry.get("banner", "")[:500],
                            "tags": ["shodan", "vuln", vuln.lower()],
                        })

                    # Finding por puerto abierto sensible
                    if host_entry["port"] in (21, 22, 23, 25, 3389, 5900, 6379, 27017):
                        findings.append({
                            "title": f"Puerto sensible {host_entry['port']} abierto ({host_entry['ip']})",
                            "severity": "medium",
                            "description": (
                                f"Shodan detectó el puerto {host_entry['port']} "
                                f"({host_entry.get('service','')}) abierto en {host_entry['ip']}"
                            ),
                            "host": host_entry["ip"],
                            "evidence": host_entry.get("banner", "")[:300],
                            "tags": ["shodan", "open-port"],
                        })

        except shodan_lib.APIError as e:
            log.warning(f"Shodan API error: {e}")
        except Exception as e:
            log.error(f"Error en Shodan recon: {e}")

        # Guardar findings
        for f in findings:
            self.storage.add_finding(
                title=f["title"],
                severity=f["severity"],
                module=self.MODULE_NAME,
                description=f["description"],
                host=f["host"],
                evidence=f.get("evidence", ""),
                tags=f.get("tags", ["shodan"]),
            )

        result = {
            "domain": domain,
            "hosts":  hosts_data,
            "total":  len(hosts_data),
        }
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] Shodan: [bold]{len(hosts_data)}[/] hosts, "
            f"[bold]{len(findings)}[/] findings"
        )
        return result

    def _parse_match(self, match: dict, domain: str) -> dict | None:
        try:
            ip      = match.get("ip_str", "")
            port    = match.get("port", 0)
            banner  = match.get("data", "")
            org     = match.get("org", "")
            product = match.get("product", "")
            version = match.get("version", "")
            vulns   = list(match.get("vulns", {}).keys())
            hostnames = match.get("hostnames", [])
            transport = match.get("transport", "tcp")

            return {
                "ip":        ip,
                "port":      port,
                "protocol":  transport,
                "service":   product or match.get("_shodan", {}).get("module", ""),
                "version":   version,
                "org":       org,
                "hostnames": hostnames,
                "vulns":     vulns,
                "banner":    banner[:1000] if banner else "",
            }
        except Exception:
            return None
