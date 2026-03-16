"""
Wrapper para katana (ProjectDiscovery) — web crawler.
Descubre endpoints, formularios y parámetros interesantes.
Si katana no está disponible, usa requests + BeautifulSoup como fallback.
"""
import json
import re
import os
import tempfile
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("crawl.katana")

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


class KatanaRunner:
    MODULE_NAME = "crawl"
    TOOL = "katana"

    # Parámetros GET interesantes para XSS/SQLi testing
    INTERESTING_PARAMS = {
        "id", "user", "username", "name", "email", "search", "q", "query",
        "page", "file", "path", "url", "redirect", "return", "next",
        "token", "key", "api_key", "callback", "cmd", "exec",
        "data", "input", "text", "msg", "message", "comment",
    }

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("crawl", {})
        self.available = check_tool(self.TOOL)
        self.depth    = self.cfg.get("depth", 3)
        self.max_urls = self.cfg.get("max_urls", 500)

    def run(self, urls: list[str]) -> dict:
        """
        Crawlea las URLs y descubre endpoints.
        Retorna dict con endpoints, forms y parámetros interesantes.
        """
        if not urls:
            return {"endpoints": [], "forms": [], "interesting_params": [], "total": 0}

        console.print(f"  [module]Katana Crawler[/] → {len(urls)} URLs (depth={self.depth})")

        all_endpoints = []
        all_forms     = []
        interesting   = []

        for url in urls[:5]:  # limitar seeds
            if self.available:
                eps, forms = self._run_katana(url)
            else:
                eps, forms = self._run_fallback(url)

            all_endpoints.extend(eps)
            all_forms.extend(forms)

        # Deduplicar
        seen  = set()
        deduped_eps = []
        for ep in all_endpoints:
            ep_url = ep.get("url", "")
            if ep_url and ep_url not in seen:
                seen.add(ep_url)
                deduped_eps.append(ep)

        # Encontrar URLs con parámetros GET interesantes
        for ep in deduped_eps:
            ep_url = ep.get("url", "")
            if "?" in ep_url:
                parsed = urlparse(ep_url)
                params = parse_qs(parsed.query)
                matching = [p for p in params if p.lower() in self.INTERESTING_PARAMS]
                if matching:
                    interesting.append({
                        "url":    ep_url,
                        "params": matching,
                        "reason": f"parámetros interesantes: {', '.join(matching)}",
                    })

        result = {
            "endpoints":         deduped_eps[:self.max_urls],
            "forms":             all_forms[:100],
            "interesting_params": interesting,
            "total":             len(deduped_eps),
        }
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] Crawl: [bold]{len(deduped_eps)}[/] endpoints, "
            f"[bold]{len(interesting)}[/] con params interesantes"
        )
        return result

    def _run_katana(self, url: str) -> tuple[list[dict], list[dict]]:
        """Ejecuta katana y parsea el output JSONL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "katana_out.json")

            cmd = [
                "katana",
                "-u",      url,
                "-d",      str(self.depth),
                "-silent",
                "-jc",     # JavaScript crawling
                "-json",
                "-o",      out_file,
            ]

            rc, stdout, stderr = run_cmd(cmd, timeout=300)

            endpoints = []
            forms     = []

            content = ""
            if os.path.exists(out_file):
                with open(out_file, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            elif stdout:
                content = stdout

            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ep_url = (
                        entry.get("endpoint")
                        or entry.get("url")
                        or entry.get("request", {}).get("endpoint")
                        or ""
                    )
                    if ep_url:
                        endpoints.append({
                            "url":    ep_url,
                            "method": entry.get("method", "GET"),
                            "source": "katana",
                        })

                    # Forms
                    for form in entry.get("request", {}).get("forms", []):
                        forms.append({
                            "url":    ep_url,
                            "method": form.get("method", "GET"),
                            "action": form.get("action", ""),
                            "inputs": form.get("inputs", []),
                        })
                except json.JSONDecodeError:
                    # Línea de texto plano con URL
                    if line.startswith("http"):
                        endpoints.append({"url": line, "method": "GET", "source": "katana"})

            return endpoints, forms

    def _run_fallback(self, start_url: str) -> tuple[list[dict], list[dict]]:
        """Fallback con requests + BeautifulSoup para crawling básico."""
        if not (_REQUESTS_OK and _BS4_OK):
            if not _REQUESTS_OK:
                log.debug("requests no disponible para crawl fallback")
            if not _BS4_OK:
                log.debug("BeautifulSoup no disponible para crawl fallback")
            return [], []

        base = urlparse(start_url)
        base_url = f"{base.scheme}://{base.netloc}"

        visited  = set()
        to_visit = [start_url]
        endpoints = []
        forms     = []

        depth = 0
        while to_visit and depth < self.depth and len(endpoints) < self.max_urls:
            next_layer = []
            for url in to_visit[:20]:  # max 20 por nivel
                if url in visited:
                    continue
                visited.add(url)

                try:
                    r = requests.get(
                        url,
                        timeout=8,
                        verify=False,
                        headers={"User-Agent": "Mozilla/5.0 OrionRecon"},
                        allow_redirects=True,
                    )
                    endpoints.append({
                        "url":    r.url,
                        "method": "GET",
                        "status": r.status_code,
                        "source": "fallback-bs4",
                    })

                    soup = BeautifulSoup(r.text, "html.parser")

                    # Extraer links
                    for tag in soup.find_all(["a", "link"], href=True):
                        href = tag.get("href", "")
                        full = urljoin(url, href)
                        p    = urlparse(full)
                        # Solo mismo dominio
                        if p.netloc == base.netloc and full not in visited:
                            next_layer.append(full)

                    # Extraer scripts
                    for tag in soup.find_all("script", src=True):
                        src = urljoin(url, tag.get("src", ""))
                        if urlparse(src).netloc == base.netloc:
                            endpoints.append({
                                "url":    src,
                                "method": "GET",
                                "status": 0,
                                "source": "script-src",
                            })

                    # Extraer formularios
                    for form in soup.find_all("form"):
                        action = urljoin(url, form.get("action", ""))
                        method = form.get("method", "GET").upper()
                        inputs = [
                            {"name": inp.get("name", ""), "type": inp.get("type", "text")}
                            for inp in form.find_all("input")
                        ]
                        forms.append({
                            "url":    url,
                            "method": method,
                            "action": action,
                            "inputs": inputs,
                        })

                except Exception as e:
                    log.debug(f"Error crawling {url}: {e}")

            to_visit = next_layer
            depth += 1

        return endpoints, forms
