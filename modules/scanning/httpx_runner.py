"""
Wrapper para httpx (ProjectDiscovery) — HTTP probing masivo.
Más rápido que requests para sondear muchos hosts.
Si httpx no está disponible, usa requests como fallback.
"""
import json
import tempfile
import os
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("scanning.httpx")


class HttpxRunner:
    MODULE_NAME = "httpx"
    TOOL = "httpx"

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("scanning", {}).get("httpx", {})
        self.available = check_tool(self.TOOL)

    def run(self, hosts: list[str]) -> list[dict]:
        """
        Sondea una lista de hosts/URLs HTTP.
        Retorna lista de {url, status, title, tech, length, redirect}.
        """
        if not hosts:
            return []

        if self.available:
            results = self._run_httpx(hosts)
        else:
            log.debug("httpx no disponible, usando fallback requests")
            results = self._run_requests_fallback(hosts)

        # Guardar resultados
        self.storage.save_module(self.MODULE_NAME, {"results": results, "total": len(results)})

        console.print(
            f"  [success]✓[/] httpx: [bold]{len(results)}[/] hosts respondieron"
        )
        return results

    def _run_httpx(self, hosts: list[str]) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = os.path.join(tmpdir, "hosts.txt")
            out_file   = os.path.join(tmpdir, "httpx_out.json")

            with open(hosts_file, "w") as f:
                f.write("\n".join(hosts))

            cmd = [
                "httpx",
                "-l", hosts_file,
                "-status-code",
                "-title",
                "-tech-detect",
                "-content-length",
                "-follow-redirects",
                "-silent",
                "-json",
                "-o", out_file,
            ]

            console.print(f"  [module]httpx[/] → {len(hosts)} hosts")
            rc, stdout, stderr = run_cmd(cmd, timeout=300)

            results = []
            # httpx emite JSONL (una línea JSON por resultado)
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
                    results.append({
                        "url":      entry.get("url", ""),
                        "status":   entry.get("status-code") or entry.get("status_code", 0),
                        "title":    entry.get("title", ""),
                        "tech":     entry.get("technologies") or entry.get("tech", []),
                        "length":   entry.get("content-length") or entry.get("content_length", 0),
                        "redirect": entry.get("final-url") or entry.get("location", ""),
                        "webserver":entry.get("webserver", ""),
                    })
                except (json.JSONDecodeError, KeyError):
                    pass

            return results

    def _run_requests_fallback(self, hosts: list[str]) -> list[dict]:
        """Fallback con requests para cuando httpx no está instalado."""
        try:
            import requests
            from concurrent.futures import ThreadPoolExecutor, as_completed
        except ImportError:
            return []

        results = []
        urls = []
        for h in hosts:
            if h.startswith(("http://", "https://")):
                urls.append(h)
            else:
                urls.append(f"https://{h}")
                urls.append(f"http://{h}")

        def probe(url: str) -> dict | None:
            try:
                r = requests.get(
                    url,
                    timeout=8,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 OrionRecon"},
                    verify=False,
                )
                title = ""
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(r.text[:5000], "html.parser")
                    t = soup.find("title")
                    if t:
                        title = t.get_text(strip=True)[:200]
                except Exception:
                    pass
                return {
                    "url":      r.url,
                    "status":   r.status_code,
                    "title":    title,
                    "tech":     [],
                    "length":   len(r.content),
                    "redirect": str(r.url) if r.url != url else "",
                    "webserver": r.headers.get("Server", ""),
                }
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(probe, u): u for u in urls}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)

        return results
