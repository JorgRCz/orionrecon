"""
Scanner de secrets en JavaScript y endpoints expuestos.
Busca API keys, tokens, passwords y claves privadas hardcodeadas.
"""
import re
import os
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("secrets.scanner")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False

# ── Patrones de secrets ────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    # AWS
    "aws_access_key":    (re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    "aws_secret":        (re.compile(r"(?i)aws.{0,20}secret.{0,10}['\"]([A-Za-z0-9/+]{40})['\"]"), "critical"),
    # Google
    "google_api_key":    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high"),
    "google_oauth":      (re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "high"),
    # Stripe
    "stripe_live_key":   (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical"),
    "stripe_pub_key":    (re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "medium"),
    # Twilio
    "twilio_account":    (re.compile(r"AC[a-zA-Z0-9]{32}"), "high"),
    "twilio_auth":       (re.compile(r"SK[a-zA-Z0-9]{32}"), "high"),
    # SendGrid
    "sendgrid_key":      (re.compile(r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43}"), "high"),
    # GitHub
    "github_token":      (re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}"), "critical"),
    # JWT
    "jwt_token":         (re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"), "high"),
    # Passwords hardcodeadas
    "password_var":      (re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]"), "medium"),
    "secret_var":        (re.compile(r"(?i)(?:secret|api_key|apikey|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]"), "medium"),
    # Private keys
    "private_key":       (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    # URLs internas
    "internal_url":      (re.compile(r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"), "low"),
    "localhost_url":     (re.compile(r"https?://(?:localhost|127\.0\.0\.1)"), "low"),
}


class SecretsScanner:
    MODULE_NAME = "secrets"

    def __init__(self, config: dict, storage: Storage):
        self.config    = config
        self.storage   = storage
        self.cfg       = config.get("scanning", {}).get("secrets", {})
        self.has_trufflehog = check_tool("trufflehog")
        self.has_gitleaks   = check_tool("gitleaks")

    def run(self, urls: list[str]) -> dict:
        """
        Busca secrets en el contenido JS de cada URL.
        Retorna dict con lista de secrets encontrados.
        """
        if not _REQUESTS_OK:
            log.warning("requests no disponible para secrets scanner")
            return {"secrets": [], "total": 0}

        console.print(f"  [module]Secrets Scanner[/] → {len(urls)} URLs")

        all_secrets = []

        # 1. Buscar JS files y escanearlos
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(self._scan_url, url): url for url in urls[:20]}
            for fut in as_completed(futures):
                url     = futures[fut]
                secrets = fut.result()
                all_secrets.extend(secrets)

        # 2. Si hay trufflehog o gitleaks, ejecutarlos en directorio temporal con los JS descargados
        if self.has_trufflehog or self.has_gitleaks:
            extra = self._run_external_tools(urls)
            all_secrets.extend(extra)

        # Deduplicar por (host, type, value)
        seen     = set()
        deduped  = []
        for s in all_secrets:
            key = (s.get("host"), s.get("type"), s.get("value", "")[:30])
            if key not in seen:
                seen.add(key)
                deduped.append(s)

        # Guardar findings
        for secret in deduped:
            self.storage.add_finding(
                title=f"Secret encontrado: {secret['type']} en {secret['host']}",
                severity=secret["severity"],
                module=self.MODULE_NAME,
                description=secret.get("description", f"Posible {secret['type']} expuesto"),
                host=secret["host"],
                url=secret.get("source_url", ""),
                evidence=secret.get("context", "")[:500],
                tags=["secret", "exposure", secret["type"]],
            )

        result = {"secrets": deduped, "total": len(deduped)}
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] Secrets: [bold]{len(deduped)}[/] posibles secrets encontrados"
        )
        return result

    def _scan_url(self, url: str) -> list[dict]:
        """Descarga el HTML de una URL, encuentra JS files y los escanea."""
        secrets = []
        host    = re.sub(r"https?://", "", url).split("/")[0]

        try:
            r = requests.get(
                url,
                timeout=10,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 OrionRecon"},
            )
            html = r.text

            # Escanear el HTML directamente
            secrets.extend(self._scan_content(html, url, host))

            # Encontrar JS files referenciados
            js_urls = self._extract_js_urls(html, url)
            for js_url in js_urls[:20]:  # limitar
                try:
                    js_r = requests.get(
                        js_url,
                        timeout=10,
                        verify=False,
                        headers={"User-Agent": "Mozilla/5.0 OrionRecon"},
                    )
                    secrets.extend(self._scan_content(js_r.text, js_url, host))
                except Exception as e:
                    log.debug(f"JS fetch error {js_url}: {e}")

        except Exception as e:
            log.debug(f"Error escaneando {url}: {e}")

        return secrets

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extrae URLs de archivos JavaScript del HTML."""
        js_urls = []
        from urllib.parse import urljoin, urlparse

        if _BS4_OK:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script", src=True):
                src = tag.get("src", "")
                if src:
                    js_urls.append(urljoin(base_url, src))
        else:
            # Fallback con regex
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = m.group(1)
                from urllib.parse import urljoin
                js_urls.append(urljoin(base_url, src))

        # Solo .js files
        return [u for u in js_urls if ".js" in u.split("?")[0] or not "." in u.split("/")[-1].split("?")[0]]

    def _scan_content(self, content: str, source_url: str, host: str) -> list[dict]:
        """Busca secrets en el contenido de texto usando regex."""
        found  = []
        lines  = content.splitlines()

        for pattern_name, (pattern, severity) in SECRET_PATTERNS.items():
            for i, line in enumerate(lines):
                for m in pattern.finditer(line):
                    value   = m.group(0)
                    context = line.strip()[:200]

                    found.append({
                        "type":        pattern_name,
                        "severity":    severity,
                        "value":       value[:80],
                        "context":     context,
                        "source_url":  source_url,
                        "host":        host,
                        "line":        i + 1,
                        "description": f"Posible {pattern_name} encontrado en {source_url}",
                    })

        return found

    def _run_external_tools(self, urls: list[str]) -> list[dict]:
        """Descarga JS a disco y corre trufflehog o gitleaks."""
        secrets = []
        if not _REQUESTS_OK:
            return secrets

        with tempfile.TemporaryDirectory() as tmpdir:
            # Descargar JS files
            js_dir = os.path.join(tmpdir, "js")
            os.makedirs(js_dir, exist_ok=True)
            downloaded = 0

            for url in urls[:10]:
                try:
                    r = requests.get(url, timeout=8, verify=False,
                                     headers={"User-Agent": "Mozilla/5.0"})
                    fname = re.sub(r"[^a-z0-9]", "_", url.lower())[:50] + ".js"
                    with open(os.path.join(js_dir, fname), "w", encoding="utf-8", errors="replace") as f:
                        f.write(r.text)
                    downloaded += 1
                except Exception as e:
                    log.debug(f"JS download error {url}: {e}")

            if not downloaded:
                return secrets

            # trufflehog
            if self.has_trufflehog:
                rc, stdout, stderr = run_cmd(
                    ["trufflehog", "filesystem", "--json", js_dir],
                    timeout=120,
                )
                for line in stdout.splitlines():
                    try:
                        import json
                        entry = json.loads(line)
                        secrets.append({
                            "type":        entry.get("DetectorName", "trufflehog"),
                            "severity":    "high",
                            "value":       entry.get("Raw", "")[:80],
                            "context":     entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                            "source_url":  urls[0] if urls else "",
                            "host":        re.sub(r"https?://", "", urls[0]).split("/")[0] if urls else "",
                            "description": f"trufflehog detectó: {entry.get('DetectorName', '')}",
                        })
                    except Exception as e:
                        log.debug(f"trufflehog output parse error: {e}")

            # gitleaks
            if self.has_gitleaks:
                out_file = os.path.join(tmpdir, "gitleaks.json")
                rc, stdout, stderr = run_cmd(
                    ["gitleaks", "detect", "--source", js_dir,
                     "--report-format", "json", "--report-path", out_file, "--no-git"],
                    timeout=120,
                )
                if os.path.exists(out_file):
                    try:
                        import json
                        with open(out_file) as f:
                            data = json.load(f)
                        for entry in (data or []):
                            secrets.append({
                                "type":        entry.get("RuleID", "gitleaks"),
                                "severity":    "high",
                                "value":       entry.get("Secret", "")[:80],
                                "context":     entry.get("Match", "")[:200],
                                "source_url":  urls[0] if urls else "",
                                "host":        re.sub(r"https?://", "", urls[0]).split("/")[0] if urls else "",
                                "description": f"gitleaks detectó: {entry.get('RuleID', '')}",
                            })
                    except Exception as e:
                        log.debug(f"gitleaks output parse error: {e}")

        return secrets
