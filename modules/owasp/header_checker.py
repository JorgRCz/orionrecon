"""
OWASP A05:2021 — Security Misconfiguration
OWASP A02:2021 — Cryptographic Failures  (cookie Secure / HSTS)
OWASP A07:2021 — Auth Failures           (cookie HttpOnly / SameSite)

Comprueba:
  · Headers de seguridad HTTP ausentes o mal configurados
  · Flags de seguridad en cookies (HttpOnly, Secure, SameSite)
  · Disclosure de tecnología en headers (Server, X-Powered-By)
"""
from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("owasp.headers")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _OK = True
except ImportError:
    _OK = False

MODULE_NAME = "header_check"

# ── Definición de headers de seguridad esperados ──────────────────────────────
# (header_lower, descripción, severidad si ausente, OWASP)
SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    (
        "strict-transport-security",
        "HSTS — fuerza HTTPS y protege contra downgrade attacks",
        "high",
        "A02",
    ),
    (
        "content-security-policy",
        "CSP — mitiga XSS y ataques de inyección de contenido",
        "high",
        "A05",
    ),
    (
        "x-frame-options",
        "Clickjacking — impide embeber la página en iframes",
        "medium",
        "A05",
    ),
    (
        "x-content-type-options",
        "MIME sniffing — evita que el browser interprete tipos MIME incorrectos",
        "medium",
        "A05",
    ),
    (
        "referrer-policy",
        "Referrer Policy — controla qué información de referrer se envía",
        "low",
        "A05",
    ),
    (
        "permissions-policy",
        "Permissions Policy — restringe APIs del browser (cámara, micrófono, etc.)",
        "low",
        "A05",
    ),
    (
        "x-xss-protection",
        "XSS Protection — activa filtro XSS del browser (legacy, complementario a CSP)",
        "info",
        "A03",
    ),
    (
        "cache-control",
        "Cache-Control — previene caché de respuestas sensibles",
        "info",
        "A02",
    ),
]

# Headers que revelan tecnología y no deberían estar expuestos
DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wp-total",
    "x-runtime",
    "x-rails-version",
]


class HeaderChecker:
    MODULE_NAME = MODULE_NAME

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("owasp", {}).get("headers", {})
        self.timeout = self.cfg.get("timeout", 12)

    def run(self, urls: list[str]) -> dict:
        if not _OK:
            log.warning("requests no disponible para HeaderChecker")
            return {"results": {}, "total_checked": 0}

        console.rule("[module] OWASP A05 — Security Headers [/]")
        console.print(f"  [module]HeaderChecker[/] → {len(urls)} URLs")

        all_results: dict[str, dict] = {}

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(self._check_url, url): url for url in urls}
            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    result = fut.result()
                    if result:
                        all_results[url] = result
                        self._generate_findings(url, result)
                except Exception as e:
                    log.debug(f"Error chequeando headers {url}: {e}")

        data = {
            "results":       all_results,
            "total_checked": len(all_results),
        }
        self.storage.save_module(self.MODULE_NAME, data)

        total_issues = sum(
            len(r.get("missing_headers", [])) + len(r.get("cookie_issues", [])) + len(r.get("disclosure", []))
            for r in all_results.values()
        )
        console.print(
            f"  [success]✓[/] Headers: {len(all_results)} URLs · "
            f"[bold]{total_issues}[/] issues encontrados"
        )
        return data

    def _check_url(self, url: str) -> dict | None:
        try:
            resp = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 OrionRecon/1.0"},
            )
        except Exception:
            return None

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        missing_headers = []
        for hdr, desc, sev, owasp in SECURITY_HEADERS:
            if hdr not in headers_lower:
                missing_headers.append({
                    "header":  hdr,
                    "desc":    desc,
                    "severity": sev,
                    "owasp":   owasp,
                })

        # Evaluar CSP si existe (verificar si es demasiado permisiva)
        csp_issues = []
        csp_val = headers_lower.get("content-security-policy", "")
        if csp_val:
            if "unsafe-inline" in csp_val:
                csp_issues.append("CSP contiene 'unsafe-inline' — mitiga parcialmente XSS")
            if "unsafe-eval" in csp_val:
                csp_issues.append("CSP contiene 'unsafe-eval' — permite eval() en scripts")
            if "*" in csp_val and "default-src" in csp_val:
                csp_issues.append("CSP usa wildcard '*' en default-src — demasiado permisiva")

        # Headers de disclosure
        disclosure = []
        for hdr in DISCLOSURE_HEADERS:
            val = headers_lower.get(hdr, "")
            if val:
                disclosure.append({"header": hdr, "value": val})

        # Cookies
        cookie_issues = self._check_cookies(resp)

        # HSTS: si existe, comprobar max-age
        hsts_issues = []
        hsts = headers_lower.get("strict-transport-security", "")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if m and int(m.group(1)) < 15552000:  # < 180 días
                hsts_issues.append(f"HSTS max-age demasiado bajo: {m.group(1)}s (recomendado ≥ 15552000)")
            if "includesubdomains" not in hsts.lower():
                hsts_issues.append("HSTS sin includeSubDomains")

        return {
            "status_code":      resp.status_code,
            "missing_headers":  missing_headers,
            "csp_issues":       csp_issues,
            "hsts_issues":      hsts_issues,
            "disclosure":       disclosure,
            "cookie_issues":    cookie_issues,
            "score":            self._compute_score(missing_headers, disclosure, cookie_issues),
        }

    def _check_cookies(self, resp: "requests.Response") -> list[dict]:
        issues = []
        for cookie in resp.cookies:
            name   = cookie.name
            flags  = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not cookie.has_nonstandard_attr("httponly"):
                # requests normalizes; check via Set-Cookie header raw
                pass

        # Parsear Set-Cookie desde headers raw
        raw_cookies = resp.headers.get("set-cookie", "")
        if not raw_cookies:
            return issues

        # Puede haber múltiples Set-Cookie — requests junta en uno, usar _store
        for name, morsel in resp.cookies._cookies.get("", {}).get("", {}).items() if resp.cookies._cookies else {}:
            pass

        # Más confiable: parsear desde response.headers directamente
        set_cookie_headers: list[str] = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

        for sc in set_cookie_headers:
            parts = [p.strip().lower() for p in sc.split(";")]
            cookie_name = sc.split("=")[0].strip() if "=" in sc else sc.split(";")[0].strip()
            flags_present = set(parts[1:])  # todo excepto name=value

            missing_flags = []
            if "httponly" not in flags_present:
                missing_flags.append({
                    "flag": "HttpOnly",
                    "severity": "medium",
                    "owasp": "A07",
                    "desc": "Cookie sin HttpOnly: accesible via JavaScript (XSS cookie theft)",
                })
            if "secure" not in flags_present:
                missing_flags.append({
                    "flag": "Secure",
                    "severity": "medium",
                    "owasp": "A02",
                    "desc": "Cookie sin Secure: puede transmitirse en HTTP plano",
                })
            samesite = next((p for p in flags_present if p.startswith("samesite")), None)
            if not samesite:
                missing_flags.append({
                    "flag": "SameSite",
                    "severity": "low",
                    "owasp": "A01",
                    "desc": "Cookie sin SameSite: susceptible a CSRF cross-site",
                })
            elif "samesite=none" in flags_present and "secure" not in flags_present:
                missing_flags.append({
                    "flag": "SameSite=None sin Secure",
                    "severity": "medium",
                    "owasp": "A02",
                    "desc": "SameSite=None requiere Secure flag",
                })

            if missing_flags:
                issues.append({
                    "cookie": cookie_name,
                    "missing_flags": missing_flags,
                })

        return issues

    def _compute_score(
        self,
        missing: list,
        disclosure: list,
        cookies: list,
    ) -> str:
        """Score de seguridad de headers: A (bueno) → F (muy malo)."""
        penalty = 0
        for h in missing:
            sev = h.get("severity", "info")
            penalty += {"high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)
        penalty += len(disclosure)
        for c in cookies:
            penalty += len(c.get("missing_flags", []))

        if penalty == 0:
            return "A"
        elif penalty <= 2:
            return "B"
        elif penalty <= 5:
            return "C"
        elif penalty <= 9:
            return "D"
        else:
            return "F"

    def _generate_findings(self, url: str, result: dict):
        host = re.sub(r"https?://", "", url).split("/")[0]

        # Findings por headers críticos ausentes
        critical_missing = [h for h in result.get("missing_headers", []) if h["severity"] in ("high", "medium")]
        if critical_missing:
            headers_list = ", ".join(h["header"] for h in critical_missing)
            self.storage.add_finding(
                title=f"Headers de seguridad ausentes en {host}",
                severity="medium",
                module=self.MODULE_NAME,
                description=(
                    f"Los siguientes headers de seguridad no están presentes en {url}:\n"
                    + "\n".join(f"  · {h['header']}: {h['desc']}" for h in critical_missing)
                ),
                host=host,
                url=url,
                evidence=f"Headers faltantes: {headers_list}",
                tags=["headers", "misconfiguration", "A05"],
            )

        # HSTS ausente o mal configurado — severidad alta
        hsts_missing = next((h for h in result.get("missing_headers", []) if h["header"] == "strict-transport-security"), None)
        if hsts_missing and url.startswith("https"):
            self.storage.add_finding(
                title=f"HSTS ausente en {host}",
                severity="high",
                module=self.MODULE_NAME,
                description=f"El servidor HTTPS {host} no envía Strict-Transport-Security. "
                             "Permite ataques de downgrade HTTPS→HTTP y MITM.",
                host=host,
                url=url,
                evidence="Header Strict-Transport-Security no presente en la respuesta.",
                tags=["hsts", "tls", "downgrade", "A02"],
            )

        # CSP ausente — alta
        csp_missing = next((h for h in result.get("missing_headers", []) if h["header"] == "content-security-policy"), None)
        if csp_missing:
            self.storage.add_finding(
                title=f"Content-Security-Policy ausente en {host}",
                severity="high",
                module=self.MODULE_NAME,
                description=f"Sin CSP en {host}, el navegador no tiene restricciones sobre "
                             "carga de scripts/estilos externos. Amplifica el impacto de XSS.",
                host=host,
                url=url,
                evidence="Header Content-Security-Policy no presente.",
                tags=["csp", "xss", "A05"],
            )

        # CSP débil
        for issue in result.get("csp_issues", []):
            self.storage.add_finding(
                title=f"CSP débil en {host}: {issue}",
                severity="medium",
                module=self.MODULE_NAME,
                description=f"La política CSP de {host} tiene configuración insegura: {issue}",
                host=host,
                url=url,
                evidence=f"Content-Security-Policy: {issue}",
                tags=["csp", "xss", "A05"],
            )

        # Disclosure de tecnología
        for d in result.get("disclosure", []):
            self.storage.add_finding(
                title=f"Información tecnológica expuesta: {d['header']} en {host}",
                severity="low",
                module=self.MODULE_NAME,
                description=f"El header {d['header']} revela información sobre el stack tecnológico: {d['value']}",
                host=host,
                url=url,
                evidence=f"{d['header']}: {d['value']}",
                tags=["disclosure", "fingerprint", "A05"],
            )

        # Cookie issues
        for ci in result.get("cookie_issues", []):
            for mf in ci.get("missing_flags", []):
                if mf["severity"] in ("medium", "high"):
                    self.storage.add_finding(
                        title=f"Cookie '{ci['cookie']}' sin {mf['flag']} en {host}",
                        severity=mf["severity"],
                        module=self.MODULE_NAME,
                        description=mf["desc"],
                        host=host,
                        url=url,
                        evidence=f"Cookie: {ci['cookie']} — falta flag {mf['flag']}",
                        tags=["cookie", mf["owasp"], mf["flag"].lower().replace(" ", "-")],
                    )
