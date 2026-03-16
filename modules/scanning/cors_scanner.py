"""
Scanner nativo de CORS misconfigurations.
Prueba origines maliciosos para detectar políticas CORS permisivas.
"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("scanning.cors")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# Headers de respuesta relevantes
_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"
_ACAM = "access-control-allow-methods"


class CorsScanner:
    MODULE_NAME = "cors"

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("scanning", {}).get("cors", {})
        self.timeout = self.cfg.get("timeout", 10)

    def run(self, urls: list[str]) -> dict:
        """
        Prueba CORS misconfigurations en una lista de URLs.
        Retorna dict con vulnerabilidades encontradas.
        """
        if not _REQUESTS_OK:
            log.warning("requests no disponible para CORS scanner")
            return {"vulnerabilities": [], "total_tested": 0}

        console.print(f"  [module]CORS Scanner[/] → {len(urls)} URLs")

        all_vulns = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(self._test_url, url): url for url in urls}
            for fut in as_completed(futures):
                url    = futures[fut]
                vulns  = fut.result()
                all_vulns.extend(vulns)

        # Guardar findings
        for v in all_vulns:
            self.storage.add_finding(
                title=v["title"],
                severity=v["severity"],
                module=self.MODULE_NAME,
                description=v["description"],
                host=v["host"],
                url=v["url"],
                evidence=v["evidence"],
                tags=["cors", "misconfiguration"],
            )

        result = {
            "vulnerabilities": all_vulns,
            "total_tested":    len(urls),
        }
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] CORS: [bold]{len(all_vulns)}[/] vulnerabilidades encontradas"
        )
        return result

    def _test_url(self, url: str) -> list[dict]:
        """Prueba un URL con varios orígenes maliciosos."""
        vulns = []
        host  = re.sub(r"https?://", "", url).split("/")[0]

        # Extraer dominio base del target para construir variantes
        domain_parts = host.split(".")
        base_domain  = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else host

        test_origins = [
            "https://evil.com",
            f"https://{base_domain}.evil.com",
            f"https://evil.{base_domain}",
            "null",
            "https://attacker.com",
        ]

        for origin in test_origins:
            try:
                headers = {
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0 OrionRecon",
                }
                r = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )

                acao = r.headers.get(_ACAO, "").strip()
                acac = r.headers.get(_ACAC, "").strip().lower()
                credentials_true = acac == "true"

                if not acao:
                    continue

                vuln = None

                # Caso 1: Refleja el origen malicioso directamente
                if acao == origin:
                    severity = "critical" if credentials_true else "high"
                    vuln = {
                        "type":        "origin_reflection",
                        "origin_sent": origin,
                        "acao":        acao,
                        "credentials": credentials_true,
                        "severity":    severity,
                    }

                # Caso 2: Wildcard con credentials
                elif acao == "*" and credentials_true:
                    vuln = {
                        "type":        "wildcard_with_credentials",
                        "origin_sent": origin,
                        "acao":        acao,
                        "credentials": True,
                        "severity":    "critical",
                    }

                # Caso 3: null origin aceptado
                elif origin == "null" and acao in ("null", "*"):
                    vuln = {
                        "type":        "null_origin",
                        "origin_sent": origin,
                        "acao":        acao,
                        "credentials": credentials_true,
                        "severity":    "medium" if not credentials_true else "high",
                    }

                if vuln:
                    severity = vuln["severity"]
                    title    = f"CORS Misconfiguration ({vuln['type']}) en {host}"
                    desc     = (
                        f"El servidor acepta el origen '{origin}' → "
                        f"Access-Control-Allow-Origin: {acao}"
                    )
                    if credentials_true:
                        desc += " con Access-Control-Allow-Credentials: true"

                    evidence = (
                        f"Origin: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}\n"
                        f"Access-Control-Allow-Methods: {r.headers.get(_ACAM, '')}"
                    )

                    vulns.append({
                        "title":       title,
                        "severity":    severity,
                        "description": desc,
                        "host":        host,
                        "url":         url,
                        "evidence":    evidence,
                        **vuln,
                    })
                    # Una vez encontrado el peor caso para este origen, continuar
                    if severity == "critical":
                        break

            except Exception:
                pass

        return vulns
