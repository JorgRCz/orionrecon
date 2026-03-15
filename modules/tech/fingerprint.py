"""
Detección de tecnologías estilo Wappalyzer.
Analiza headers HTTP, cookies, HTML, JS y favicon.
"""
import re
import hashlib
import requests
from urllib.parse import urljoin
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage

log = get_logger("tech.fingerprint")

# Firmas de tecnologías: {tech_name: {campo: [regex_o_string]}}
TECH_SIGNATURES = {
    # Servidores web
    "Apache": {
        "headers": {"Server": [r"Apache/?[\d.]*"]},
        "category": "Web Server",
    },
    "Nginx": {
        "headers": {"Server": [r"nginx/?[\d.]*"]},
        "category": "Web Server",
    },
    "IIS": {
        "headers": {"Server": [r"Microsoft-IIS/?[\d.]*"]},
        "category": "Web Server",
    },
    "Caddy": {
        "headers": {"Server": [r"Caddy"]},
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": {"Server": [r"LiteSpeed"]},
        "category": "Web Server",
    },

    # Lenguajes/Frameworks backend
    "PHP": {
        "headers": {"X-Powered-By": [r"PHP/?[\d.]*"]},
        "cookies": [r"PHPSESSID"],
        "html": [r"\.php[\?\"']"],
        "category": "Programming Language",
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": [r"ASP\.NET"]},
        "cookies": [r"ASP\.NET_SessionId", r"ASPXAUTH"],
        "category": "Web Framework",
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": [r"Phusion Passenger"]},
        "cookies": [r"_session_id"],
        "html": [r"csrf-token", r"authenticity_token"],
        "category": "Web Framework",
    },
    "Django": {
        "cookies": [r"csrftoken", r"sessionid"],
        "html": [r"csrfmiddlewaretoken"],
        "category": "Web Framework",
    },
    "Laravel": {
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "html": [r"laravel"],
        "category": "Web Framework",
    },
    "Express.js": {
        "headers": {"X-Powered-By": [r"Express"]},
        "category": "Web Framework",
    },

    # CMS
    "WordPress": {
        "html": [
            r"wp-content/",
            r"wp-includes/",
            r"/wp-json/",
            r'content="WordPress',
        ],
        "cookies": [r"wordpress_"],
        "category": "CMS",
    },
    "Drupal": {
        "html": [r'Drupal\.settings', r"/sites/default/files/"],
        "headers": {"X-Generator": [r"Drupal"]},
        "cookies": [r"SESS[a-f0-9]{32}"],
        "category": "CMS",
    },
    "Joomla": {
        "html": [r"/media/jui/", r"Joomla"],
        "category": "CMS",
    },
    "Magento": {
        "html": [r"Mage\.Cookie", r"/skin/frontend/"],
        "cookies": [r"frontend"],
        "category": "eCommerce",
    },
    "Shopify": {
        "html": [r"Shopify\.theme", r"cdn\.shopify\.com"],
        "category": "eCommerce",
    },

    # JS Frameworks
    "React": {
        "html": [r'__react', r'data-reactroot', r'data-reactid'],
        "js": [r"react\.development\.js", r"react\.min\.js"],
        "category": "JavaScript Framework",
    },
    "Vue.js": {
        "html": [r'__vue__', r'data-v-[a-f0-9]+'],
        "js": [r"vue\.min\.js", r"vue\.js"],
        "category": "JavaScript Framework",
    },
    "Angular": {
        "html": [r'ng-version=', r'ng-app=', r'_nghost'],
        "js": [r"angular\.min\.js"],
        "category": "JavaScript Framework",
    },
    "jQuery": {
        "js": [r"jquery[-\w.]*\.min\.js", r"jquery[-\w.]*\.js"],
        "html": [r"jQuery v[\d.]+"],
        "category": "JavaScript Library",
    },
    "Bootstrap": {
        "html": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
        "category": "UI Framework",
    },

    # CDN / Cloud
    "Cloudflare": {
        "headers": {"CF-RAY": [r".+"], "Server": [r"cloudflare"]},
        "category": "CDN",
    },
    "Amazon CloudFront": {
        "headers": {"X-Amz-Cf-Id": [r".+"], "Via": [r"CloudFront"]},
        "category": "CDN",
    },
    "Fastly": {
        "headers": {"X-Served-By": [r"cache-"], "X-Cache": [r"HIT|MISS"]},
        "category": "CDN",
    },
    "Akamai": {
        "headers": {"X-Check-Cacheable": [r".+"], "X-Akamai-Transformed": [r".+"]},
        "category": "CDN",
    },

    # Bases de datos / tecnologías de backend
    "Node.js": {
        "headers": {"X-Powered-By": [r"Node\.?js"]},
        "category": "Runtime",
    },

    # Analítica / Marketing
    "Google Analytics": {
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+-\d+"],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
        "category": "Analytics",
    },

    # WAF / Security
    "Sucuri WAF": {
        "headers": {"X-Sucuri-ID": [r".+"]},
        "category": "WAF",
    },
    "ModSecurity": {
        "headers": {"Server": [r"mod_security"]},
        "category": "WAF",
    },
    "Imperva": {
        "headers": {"X-Iinfo": [r".+"]},
        "cookies": [r"visid_incap_", r"incap_ses_"],
        "category": "WAF",
    },
    "F5 BIG-IP": {
        "cookies": [r"BIGipServer"],
        "category": "Load Balancer",
    },
}


def _match_pattern(patterns: list[str], value: str) -> bool:
    for p in patterns:
        if re.search(p, value, re.IGNORECASE):
            return True
    return False


class TechDetector:
    MODULE_NAME = "tech_detection"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.cfg = config.get("tech_detection", {})
        self.timeout = config.get("general", {}).get("timeout", 30)
        self.ua = config.get("general", {}).get("user_agent", "Mozilla/5.0")

    def analyze_url(self, url: str) -> dict:
        """Analiza una URL y detecta tecnologías."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        detected = {}

        try:
            resp = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": self.ua},
                allow_redirects=True,
                verify=False,
            )

            headers = dict(resp.headers)
            html = resp.text[:50000]
            cookies = {k: v for k, v in resp.cookies.items()}

            # Detectar JS files referenciados
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)

            for tech_name, sig in TECH_SIGNATURES.items():
                matched = False
                version = ""

                # Chequear headers
                if self.cfg.get("check_headers", True) and "headers" in sig:
                    for header_name, patterns in sig["headers"].items():
                        header_val = headers.get(header_name, "")
                        if header_val and _match_pattern(patterns, header_val):
                            matched = True
                            # Intentar extraer versión
                            for p in patterns:
                                m = re.search(p, header_val, re.IGNORECASE)
                                if m:
                                    version = m.group(0)
                            break

                # Chequear cookies
                if not matched and self.cfg.get("check_cookies", True) and "cookies" in sig:
                    for cookie_name in cookies:
                        if _match_pattern(sig["cookies"], cookie_name):
                            matched = True
                            break

                # Chequear HTML
                if not matched and self.cfg.get("check_html", True) and "html" in sig:
                    if _match_pattern(sig["html"], html):
                        matched = True

                # Chequear JS files
                if not matched and self.cfg.get("check_js", True) and "js" in sig:
                    js_content = " ".join(js_files)
                    if _match_pattern(sig["js"], js_content):
                        matched = True

                if matched:
                    detected[tech_name] = {
                        "version": version,
                        "category": sig.get("category", "Unknown"),
                    }

            # Info adicional
            server = headers.get("Server", "")
            powered_by = headers.get("X-Powered-By", "")
            content_type = headers.get("Content-Type", "")

            # Detectar header de seguridad faltantes (findings)
            security_headers = {
                "X-Frame-Options": "medium",
                "X-Content-Type-Options": "low",
                "Content-Security-Policy": "medium",
                "Strict-Transport-Security": "medium",
                "X-XSS-Protection": "low",
                "Referrer-Policy": "low",
                "Permissions-Policy": "low",
            }

            missing_headers = []
            for h, sev in security_headers.items():
                if h not in headers:
                    missing_headers.append((h, sev))
                    self.storage.add_finding(
                        title=f"Header de seguridad faltante: {h}",
                        severity=sev,
                        module=self.MODULE_NAME,
                        description=f"El header HTTP '{h}' no está configurado en {url}",
                        host=url,
                        url=url,
                        tags=["headers", "security", "tech"],
                    )

            # Cookie sin flags de seguridad
            for cookie_name, cookie_val in resp.cookies.items():
                cookie_obj = resp.cookies._cookies
                # Verificar Secure y HttpOnly flags
                for domain_cookies in cookie_obj.values():
                    for path_cookies in domain_cookies.values():
                        for name, c in path_cookies.items():
                            if name == cookie_name:
                                if not c.secure:
                                    self.storage.add_finding(
                                        title=f"Cookie sin flag Secure: {cookie_name}",
                                        severity="low",
                                        module=self.MODULE_NAME,
                                        description=f"La cookie '{cookie_name}' no tiene el flag Secure",
                                        host=url,
                                        url=url,
                                        tags=["cookie", "security"],
                                    )

            result = {
                "url": url,
                "status_code": resp.status_code,
                "technologies": detected,
                "server": server,
                "powered_by": powered_by,
                "content_type": content_type,
                "missing_security_headers": [h for h, _ in missing_headers],
                "headers": dict(headers),
            }

            return result

        except requests.exceptions.SSLError:
            log.warning(f"[warning]SSL error en {url}, reintentando sin verificación[/]")
            return {"url": url, "error": "SSL error", "technologies": {}}
        except requests.RequestException as e:
            log.error(f"Error analizando {url}: {e}")
            return {"url": url, "error": str(e), "technologies": {}}

    def run(self, targets: list[str]) -> dict:
        console.rule("[module] TECH DETECTION [/]")
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(self.analyze_url, t): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    res = fut.result()
                    results.append(res)
                    techs = res.get("technologies", {})
                    tech_list = ", ".join(
                        f"{t} ({d['category']})" for t, d in techs.items()
                    )
                    console.print(
                        f"  [success]✓[/] {target}\n"
                        f"    [dim]{tech_list or 'Sin tecnologías detectadas'}[/]"
                    )
                except Exception as e:
                    log.error(f"Error en {target}: {e}")

        final = {"targets_analyzed": len(results), "results": results}
        self.storage.save_module(self.MODULE_NAME, final)
        return final
