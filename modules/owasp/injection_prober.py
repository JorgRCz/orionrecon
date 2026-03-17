"""
OWASP A03:2021 — Injection (SQL Injection, Reflected XSS)
OWASP A10:2021 — Server-Side Request Forgery (SSRF)
OWASP A01:2021 — Broken Access Control (Path Traversal)

Modo: DETECCIÓN ÚNICAMENTE — no explota, solo detecta indicadores de vulnerabilidad.

Estrategia:
  · Recopila URLs con parámetros de: crawl, GAU, fuzzing
  · Para cada URL, prueba cada parámetro con payloads mínimos
  · SQLi: detecta mensajes de error de BD en la respuesta
  · XSS: inyecta marker único y verifica reflexión sin encoding
  · SSRF: identifica parámetros típicos de SSRF (flag informacional)
  · LFI/Path Traversal: detecta contenido de /etc/passwd en respuesta
"""
from __future__ import annotations
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("owasp.injection")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _OK = True
except ImportError:
    _OK = False

MODULE_NAME = "injection"

# ── SQLi: payloads de detección de errores ─────────────────────────────────
_SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1; --", "1' AND SLEEP(0)--"]

# Patrones de error de BD en respuesta (error-based detection)
_SQLI_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"Microsoft OLE DB|ODBC SQL|SQLite3::query|"
    r"Unclosed quotation mark|supplied argument is not a valid MySQL|"
    r"Warning.*mysql_.*\(\)|You have an error in your SQL syntax|"
    r"pg_query\(\)|ERROR: syntax error at or near|"
    r"SQLSTATE\[|microsoft jet database|syntax error.*from clause)",
    re.IGNORECASE,
)

# ── XSS Reflected: marker único ───────────────────────────────────────────
_XSS_MARKER   = "OrionXSSprobe9f3a"
_XSS_PAYLOADS = [
    f"<{_XSS_MARKER}>",
    f'"><{_XSS_MARKER}>',
    f"'><{_XSS_MARKER}>",
    f"javascript:{_XSS_MARKER}",
]

# ── SSRF: parámetros típicos ──────────────────────────────────────────────
_SSRF_PARAMS = {
    "url", "uri", "redirect", "next", "return", "returnto", "returnurl",
    "goto", "to", "href", "link", "src", "source", "path", "dest",
    "destination", "file", "document", "fetch", "request", "host",
    "endpoint", "proxy", "forward", "callback", "out", "view",
    "load", "include", "page", "dir", "feed", "webhook",
}

# ── LFI: payloads de detección ────────────────────────────────────────────
_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
]
_LFI_MARKER = re.compile(r"root:.*:0:0:", re.IGNORECASE)


class InjectionProber:
    MODULE_NAME = MODULE_NAME
    MAX_URLS    = 80    # máximo de URLs a probar
    MAX_PARAMS  = 6     # máximo de parámetros por URL
    DELAY       = 0.15  # delay entre requests para no ser agresivo

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("owasp", {}).get("injection", {})
        self.timeout = self.cfg.get("timeout", 10)

    def run(self, storage_data: dict | None = None) -> dict:
        """
        Recibe los datos del storage para extraer URLs con parámetros.
        storage_data: self.storage.data
        """
        if not _OK:
            log.warning("requests no disponible para InjectionProber")
            return {"sqli": [], "xss": [], "ssrf_params": [], "lfi": [], "total_tested": 0}

        console.rule("[module] OWASP A03/A10 — Injection & SSRF [/]")

        # Recopilar URLs con parámetros de las distintas fuentes
        param_urls = self._collect_param_urls(storage_data or {})
        if not param_urls:
            console.print("  [dim]Sin URLs con parámetros para probar[/]")
            result = {"sqli": [], "xss": [], "ssrf_params": [], "lfi": [], "total_tested": 0}
            self.storage.save_module(self.MODULE_NAME, result)
            return result

        console.print(f"  [module]InjectionProber[/] → {len(param_urls)} URLs con parámetros")

        sqli_findings: list[dict] = []
        xss_findings:  list[dict] = []
        ssrf_flags:    list[dict] = []
        lfi_findings:  list[dict] = []

        # Detectar SSRF params (sin hacer requests activos — flag informacional)
        ssrf_flags = self._detect_ssrf_params(param_urls)

        # Probar SQLi y XSS en paralelo moderado
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {
                ex.submit(self._probe_url, url): url
                for url in param_urls[: self.MAX_URLS]
            }
            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    r = fut.result()
                    sqli_findings.extend(r.get("sqli", []))
                    xss_findings.extend(r.get("xss", []))
                    lfi_findings.extend(r.get("lfi", []))
                except Exception as e:
                    log.debug(f"Probe error {url}: {e}")

        # Generar findings
        for f in sqli_findings:
            self._add_finding_sqli(f)
        for f in xss_findings:
            self._add_finding_xss(f)
        for f in lfi_findings:
            self._add_finding_lfi(f)
        for f in ssrf_flags:
            self._add_finding_ssrf(f)

        result = {
            "sqli":         sqli_findings,
            "xss":          xss_findings,
            "ssrf_params":  ssrf_flags,
            "lfi":          lfi_findings,
            "total_tested": len(param_urls),
        }
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] Injection: "
            f"[bold]{len(sqli_findings)}[/] SQLi · "
            f"[bold]{len(xss_findings)}[/] XSS · "
            f"[bold]{len(ssrf_flags)}[/] SSRF params · "
            f"[bold]{len(lfi_findings)}[/] LFI"
        )
        return result

    # ── Recopilación de URLs con parámetros ──────────────────────────────────

    def _collect_param_urls(self, data: dict) -> list[str]:
        """Extrae URLs con query-string de todas las fuentes disponibles."""
        urls: set[str] = set()
        modules = data.get("modules", {})

        # 1. Crawl (katana)
        crawl = (modules.get("crawl") or {}).get("results") or {}
        for ep in (crawl.get("endpoints") or []):
            url = ep.get("url", "")
            if "?" in url and "=" in url:
                urls.add(url)

        # 2. GAU interesting URLs
        recon = (modules.get("recon") or {}).get("results") or {}
        gau   = recon.get("gau") or {}
        for item in (gau.get("interesting") or []):
            url = item.get("url", "")
            if "?" in url and "=" in url:
                urls.add(url)

        # 3. GAU all URLs (limitado para no explotar)
        for url in (gau.get("urls") or [])[:500]:
            if "?" in url and "=" in url:
                urls.add(url)

        # 4. Fuzzing results con parámetros
        fuzz = (modules.get("fuzzing") or {}).get("results") or {}
        for _tgt, modes in (fuzz or {}).items():
            for _mode, res in (modes or {}).items():
                for r in (res.get("results") or []):
                    url = r.get("url", "")
                    if "?" in url and "=" in url and r.get("status", 0) not in (404, 0):
                        urls.add(url)

        # Limpiar: solo URLs con esquema HTTP/HTTPS
        clean = [u for u in urls if u.startswith(("http://", "https://"))]

        # Priorizar: URLs con más parámetros primero
        clean.sort(key=lambda u: u.count("&"), reverse=True)

        return clean[: self.MAX_URLS * 2]

    # ── SSRF param detection (pasivo) ────────────────────────────────────────

    def _detect_ssrf_params(self, param_urls: list[str]) -> list[dict]:
        findings = []
        seen: set[str] = set()

        for url in param_urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            host   = parsed.netloc

            ssrf_found = [p for p in params if p.lower() in _SSRF_PARAMS]
            if ssrf_found:
                key = f"{host}|{','.join(sorted(ssrf_found))}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "url":    url,
                        "host":   host,
                        "params": ssrf_found,
                    })
        return findings

    # ── Probe activo por URL ──────────────────────────────────────────────────

    def _probe_url(self, url: str) -> dict:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        host   = parsed.netloc

        sqli_hits: list[dict] = []
        xss_hits:  list[dict] = []
        lfi_hits:  list[dict] = []

        param_names = list(params.keys())[: self.MAX_PARAMS]

        for param in param_names:
            # SQLi — error based
            for payload in _SQLI_PAYLOADS[:3]:  # solo 3 payloads por param
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
                )
                try:
                    r = requests.get(
                        test_url, timeout=self.timeout, verify=False,
                        allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0 OrionRecon/1.0"},
                    )
                    if _SQLI_ERRORS.search(r.text):
                        sqli_hits.append({
                            "url":     url,
                            "host":    host,
                            "param":   param,
                            "payload": payload,
                            "evidence": _SQLI_ERRORS.search(r.text).group(0)[:200],
                        })
                        break  # un hit por parámetro es suficiente
                    time.sleep(self.DELAY)
                except Exception as e:
                    log.debug(f"SQLi probe error {url}: {e}")

            # XSS Reflected
            xss_payload = _XSS_PAYLOADS[0]
            test_params = dict(params)
            test_params[param] = [xss_payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
            )
            try:
                r = requests.get(
                    test_url, timeout=self.timeout, verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 OrionRecon/1.0"},
                )
                # Verificar que el marker esté en la respuesta sin ser HTML-encoded
                if _XSS_MARKER in r.text and "<" + _XSS_MARKER + ">" in r.text:
                    xss_hits.append({
                        "url":     url,
                        "host":    host,
                        "param":   param,
                        "payload": xss_payload,
                        "evidence": f"Marker '{_XSS_MARKER}' reflejado sin encoding en la respuesta",
                    })
                time.sleep(self.DELAY)
            except Exception as e:
                log.debug(f"XSS probe error {url}: {e}")

            # LFI / Path Traversal
            lfi_payload = _LFI_PAYLOADS[0]
            test_params = dict(params)
            test_params[param] = [lfi_payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
            )
            try:
                r = requests.get(
                    test_url, timeout=self.timeout, verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 OrionRecon/1.0"},
                )
                if _LFI_MARKER.search(r.text):
                    lfi_hits.append({
                        "url":     url,
                        "host":    host,
                        "param":   param,
                        "payload": lfi_payload,
                        "evidence": "Contenido de /etc/passwd detectado en la respuesta",
                    })
                time.sleep(self.DELAY)
            except Exception as e:
                log.debug(f"LFI probe error {url}: {e}")

        return {"sqli": sqli_hits, "xss": xss_hits, "lfi": lfi_hits}

    # ── Generación de findings ────────────────────────────────────────────────

    def _add_finding_sqli(self, f: dict):
        self.storage.add_finding(
            title=f"SQL Injection detectado: {f['host']} (param: {f['param']})",
            severity="critical",
            module=self.MODULE_NAME,
            description=(
                f"El parámetro '{f['param']}' en {f['url']} es potencialmente vulnerable "
                f"a SQL Injection. Se detectaron mensajes de error de base de datos en la respuesta. "
                f"Payload: {f['payload']}"
            ),
            host=f["host"],
            url=f["url"],
            evidence=f"Payload: {f['payload']}\nError detectado: {f['evidence']}",
            tags=["sql-injection", "injection", "A03", "database"],
        )

    def _add_finding_xss(self, f: dict):
        self.storage.add_finding(
            title=f"XSS Reflejado detectado: {f['host']} (param: {f['param']})",
            severity="high",
            module=self.MODULE_NAME,
            description=(
                f"El parámetro '{f['param']}' en {f['url']} refleja contenido HTML sin "
                f"sanitización. Un atacante puede inyectar código JavaScript malicioso."
            ),
            host=f["host"],
            url=f["url"],
            evidence=f"Payload: {f['payload']}\n{f['evidence']}",
            tags=["xss", "reflected-xss", "injection", "A03"],
        )

    def _add_finding_lfi(self, f: dict):
        self.storage.add_finding(
            title=f"Path Traversal / LFI detectado: {f['host']} (param: {f['param']})",
            severity="critical",
            module=self.MODULE_NAME,
            description=(
                f"El parámetro '{f['param']}' en {f['url']} es vulnerable a Path Traversal. "
                f"Se detectó contenido del sistema de archivos (/etc/passwd) en la respuesta."
            ),
            host=f["host"],
            url=f["url"],
            evidence=f"Payload: {f['payload']}\n{f['evidence']}",
            tags=["lfi", "path-traversal", "A01", "file-inclusion"],
        )

    def _add_finding_ssrf(self, f: dict):
        self.storage.add_finding(
            title=f"Posibles parámetros SSRF en {f['host']}: {', '.join(f['params'])}",
            severity="medium",
            module=self.MODULE_NAME,
            description=(
                f"Se detectaron parámetros típicamente asociados a vulnerabilidades SSRF en {f['url']}: "
                f"{', '.join(f['params'])}. Verificación manual recomendada con Collaborator/OAST."
            ),
            host=f["host"],
            url=f["url"],
            evidence=f"Parámetros: {', '.join(f['params'])}\nURL: {f['url']}",
            tags=["ssrf", "A10", "server-side-request-forgery"],
        )
