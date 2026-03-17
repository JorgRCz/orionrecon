"""
Detección de subdomain takeover.
Basado en firmas de can-i-take-over-xyz (https://github.com/EdOverflow/can-i-take-over-xyz)
"""
import re
import socket
import requests
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage

log = get_logger("takeover.checker")

# Base de datos de fingerprints para takeover
# Formato: {servicio: {cname_pattern, fingerprint_en_body, vulnerable, notas}}
TAKEOVER_SIGNATURES = {
    "GitHub Pages": {
        "cname": [r"github\.io$"],
        "fingerprint": ["There isn't a GitHub Pages site here", "For root URLs"],
        "vulnerable": True,
        "severity": "high",
    },
    "Heroku": {
        "cname": [r"\.herokudns\.com$", r"\.herokuapp\.com$"],
        "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "vulnerable": True,
        "severity": "high",
    },
    "Fastly": {
        "cname": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        "fingerprint": ["Fastly error: unknown domain"],
        "vulnerable": True,
        "severity": "high",
    },
    "Shopify": {
        "cname": [r"\.myshopify\.com$"],
        "fingerprint": ["Sorry, this shop is currently unavailable"],
        "vulnerable": True,
        "severity": "high",
    },
    "Tumblr": {
        "cname": [r"\.tumblr\.com$"],
        "fingerprint": ["Whatever you were looking for doesn't currently exist"],
        "vulnerable": True,
        "severity": "high",
    },
    "WP Engine": {
        "cname": [r"\.wpengine\.com$"],
        "fingerprint": ["The site you were looking for couldn't be found"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Amazon S3": {
        "cname": [r"\.s3\.amazonaws\.com$", r"\.s3-website"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "vulnerable": True,
        "severity": "high",
    },
    "Amazon CloudFront": {
        "cname": [r"\.cloudfront\.net$"],
        "fingerprint": ["ERROR: The request could not be satisfied", "Bad request"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Azure": {
        "cname": [r"\.azurewebsites\.net$", r"\.cloudapp\.net$", r"\.trafficmanager\.net$"],
        "fingerprint": ["404 Web Site not found", "The resource you are looking for has been removed"],
        "vulnerable": True,
        "severity": "high",
    },
    "Zendesk": {
        "cname": [r"\.zendesk\.com$"],
        "fingerprint": ["Help Center Closed"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Desk.com": {
        "cname": [r"\.desk\.com$"],
        "fingerprint": ["Please try again or try Desk.com free for 14 days"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Ghost": {
        "cname": [r"\.ghost\.io$"],
        "fingerprint": ["The thing you were looking for is no longer here"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Cargo": {
        "cname": [r"\.cargocollective\.com$"],
        "fingerprint": ["If you're moving your domain away from Cargo"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Bitbucket": {
        "cname": [r"\.bitbucket\.io$"],
        "fingerprint": ["Repository not found"],
        "vulnerable": True,
        "severity": "high",
    },
    "Pantheon": {
        "cname": [r"\.pantheonsite\.io$"],
        "fingerprint": ["The gods are wise, but do not know of the site"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Surge.sh": {
        "cname": [r"\.surge\.sh$"],
        "fingerprint": ["project not found"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Netlify": {
        "cname": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "fingerprint": ["Not Found - Request ID"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Vercel": {
        "cname": [r"\.vercel\.app$"],
        "fingerprint": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "vulnerable": True,
        "severity": "medium",
    },
    "Unbounce": {
        "cname": [r"\.unbouncepages\.com$"],
        "fingerprint": ["The requested URL was not found on this server"],
        "vulnerable": True,
        "severity": "medium",
    },
}


def get_cnames(domain: str, timeout: float = 5.0) -> list[str]:
    """Resuelve la cadena de CNAMEs de un dominio."""
    cnames = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        current = domain
        for _ in range(10):  # max 10 saltos CNAME
            try:
                answers = resolver.resolve(current, "CNAME")
                for ans in answers:
                    target = ans.target.to_text().rstrip(".")
                    cnames.append(target)
                    current = target
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
            except Exception as e:
                log.debug(f"CNAME chain error for {domain}: {e}")
                break
    except Exception as e:
        log.debug(f"CNAME resolve error for {domain}: {e}")
    return cnames


def check_nxdomain(domain: str) -> bool:
    """Retorna True si el dominio resuelve a NXDOMAIN."""
    try:
        socket.gethostbyname(domain)
        return False
    except socket.gaierror:
        return True


def fetch_body(url: str, timeout: float = 10.0) -> str:
    """Descarga el body de una URL, retorna string vacío si falla."""
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{url}",
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            return resp.text[:5000]
        except Exception as e:
            log.debug(f"fetch_body error for {url}: {e}")
            continue
    return ""


def check_subdomain(subdomain: str) -> dict | None:
    """
    Comprueba si un subdominio es vulnerable a takeover.
    Retorna dict con info o None si no es vulnerable.
    """
    result = {
        "subdomain": subdomain,
        "cnames": [],
        "service": None,
        "vulnerable": False,
        "severity": "info",
        "reason": "",
    }

    # 1. Obtener CNAMEs
    cnames = get_cnames(subdomain)
    result["cnames"] = cnames

    # 2. NXDOMAIN directo = posible dangling DNS
    is_nxdomain = check_nxdomain(subdomain)

    # 3. Chequear CNAME contra firmas
    all_cnames_str = " ".join(cnames).lower()

    for service, sig in TAKEOVER_SIGNATURES.items():
        cname_matched = any(
            re.search(p, cname, re.IGNORECASE)
            for p in sig["cname"]
            for cname in cnames
        )

        if not cname_matched:
            continue

        # CNAME coincide, verificar con body
        body = fetch_body(subdomain)
        body_matched = any(
            fp.lower() in body.lower()
            for fp in sig["fingerprint"]
        )

        if body_matched and sig["vulnerable"]:
            result["service"] = service
            result["vulnerable"] = True
            result["severity"] = sig["severity"]
            result["reason"] = f"CNAME → {cnames[-1] if cnames else '?'} con fingerprint de takeover"
            return result

    # 4. NXDOMAIN con CNAME = dangling DNS genérico
    if is_nxdomain and cnames:
        result["vulnerable"] = True
        result["severity"] = "medium"
        result["reason"] = f"Dangling DNS: CNAME → {cnames[-1]} pero NXDOMAIN"
        return result

    return None  # No vulnerable


class TakeoverChecker:
    MODULE_NAME = "takeover"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.cfg = config.get("takeover", {})
        self.concurrency = self.cfg.get("concurrency", 20)

    def run(self, subdomains: list[str]) -> dict:
        console.rule("[module] SUBDOMAIN TAKEOVER CHECK [/]")
        console.print(f"  Comprobando [bold]{len(subdomains)}[/] subdominios...")

        vulnerables = []

        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futures = {ex.submit(check_subdomain, s): s for s in subdomains}
            for fut in as_completed(futures):
                subdomain = futures[fut]
                try:
                    res = fut.result()
                    if res and res["vulnerable"]:
                        vulnerables.append(res)
                        badge = sev_badge(res["severity"])
                        console.print(
                            f"  {badge} [bold]{subdomain}[/]\n"
                            f"    Servicio : {res['service'] or 'Desconocido'}\n"
                            f"    CNAME    : {' → '.join(res['cnames']) or 'N/A'}\n"
                            f"    Razón    : {res['reason']}"
                        )
                        self.storage.add_finding(
                            title=f"Subdomain Takeover: {subdomain}",
                            severity=res["severity"],
                            module=self.MODULE_NAME,
                            description=f"Posible subdomain takeover vía {res['service'] or 'dangling DNS'}",
                            host=subdomain,
                            evidence=res["reason"],
                            tags=["takeover", "subdomain", res["service"] or "dangling"],
                        )
                except Exception as e:
                    log.error(f"Error chequeando {subdomain}: {e}")

        result = {
            "total_checked": len(subdomains),
            "vulnerable_count": len(vulnerables),
            "vulnerabilities": vulnerables,
        }
        self.storage.save_module(self.MODULE_NAME, result)

        if vulnerables:
            console.print(
                f"\n[critical]⚠ {len(vulnerables)} subdominios vulnerables a takeover![/]"
            )
        else:
            console.print(f"\n[success]✓[/] Sin takeovers detectados en {len(subdomains)} subdominios")

        return result
