"""
ffuf wrapper — directory fuzzing, parameter fuzzing, vhost fuzzing.
"""
import json
import tempfile
import os
import shutil
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage

log = get_logger("fuzzing.ffuf")

# Wordlists por defecto (orden de preferencia)
DEFAULT_WORDLISTS = {
    "directories": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt",
    ],
    "parameters": [
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
    ],
    "vhosts": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
}

# Códigos de status interesantes
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 500}
HIGH_VALUE_CODES = {200, 201, 301, 302}


def find_wordlist(wl_type: str, config_path: str = "") -> str | None:
    """Busca una wordlist disponible en el sistema."""
    if config_path and os.path.exists(config_path):
        return config_path

    for path in DEFAULT_WORDLISTS.get(wl_type, []):
        if os.path.exists(path):
            return path

    return None


def parse_ffuf_output(json_path: str, max_results: int = 500) -> list[dict]:
    """Parsea el output JSON de ffuf. Limita a max_results entradas más interesantes."""
    results = []
    if not os.path.exists(json_path):
        return results

    try:
        with open(json_path) as f:
            data = json.load(f)

        raw = data.get("results", [])

        # Prioridad: 200/201 > 302/307 > 301 > resto
        def _priority(r):
            s = r.get("status", 0)
            if s in (200, 201): return 0
            if s in (302, 307): return 1
            if s in (301,):     return 2
            return 3

        raw.sort(key=_priority)

        for result in raw[:max_results]:
            results.append({
                "url": result.get("url", ""),
                "status": result.get("status", 0),
                "length": result.get("length", 0),
                "words": result.get("words", 0),
                "lines": result.get("lines", 0),
                "content_type": result.get("content-type", ""),
                "redirect": result.get("redirectlocation", ""),
                "input": {k: v for k, v in result.get("input", {}).items()},
            })
    except Exception as e:
        log.error(f"Error parseando ffuf JSON: {e}")

    return results


class FfufRunner:
    MODULE_NAME = "fuzzing"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.cfg = config.get("fuzzing", {}).get("ffuf", {})
        self.available = check_tool("ffuf")
        self.threads = self.cfg.get("threads", 40)
        self.timeout = self.cfg.get("timeout", 10)

    def _build_base_cmd(
        self,
        url: str,
        wordlist: str,
        out_file: str,
        extra_flags: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-o", out_file,
            "-of", "json",
            "-s",  # silent
        ]

        # Filtrar códigos sin interés (usar config si existe)
        fc = self.cfg.get("filter_codes", "400,403,404")
        cmd += ["-fc", fc]

        if extra_flags:
            cmd.extend(extra_flags)

        return cmd

    def fuzz_directories(self, base_url: str) -> dict:
        """Fuzzing de directorios y archivos."""
        console.print(f"\n  [module]ffuf dirs[/] → {base_url}")

        wl_path = find_wordlist(
            "directories",
            self.cfg.get("wordlists", {}).get("directories", "")
        )
        if not wl_path:
            log.warning("[warning]Wordlist de directorios no encontrada[/]")
            return {"error": "wordlist not found", "results": []}

        url = base_url.rstrip("/") + "/FUZZ"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        try:
            cmd = self._build_base_cmd(url, wl_path, out_path)
            rc, stdout, stderr = run_cmd(cmd, timeout=600)
            results = parse_ffuf_output(out_path)

            # Crear findings para paths interesantes
            for r in results:
                status = r["status"]
                path_url = r["url"]

                if status in HIGH_VALUE_CODES:
                    sev = "low"
                    if any(
                        keyword in path_url.lower()
                        for keyword in ["admin", "backup", "config", ".git", ".env",
                                        "api", "swagger", "phpinfo", "debug", "console"]
                    ):
                        sev = "medium"
                    if any(
                        keyword in path_url.lower()
                        for keyword in [".git", ".env", "backup", "dump", "sql"]
                    ):
                        sev = "high"

                    self.storage.add_finding(
                        title=f"Directorio/archivo accesible: {path_url}",
                        severity=sev,
                        module=self.MODULE_NAME,
                        description=f"HTTP {status} en {path_url}",
                        host=base_url,
                        url=path_url,
                        evidence=f"Status: {status} | Length: {r['length']}",
                        tags=["fuzzing", "directory", f"http-{status}"],
                    )

            console.print(
                f"  [success]✓[/] Dirs: [bold]{len(results)}[/] paths encontrados "
                f"({len([r for r in results if r['status'] in HIGH_VALUE_CODES])} interesantes)"
            )
            return {"mode": "directories", "url": url, "results": results}

        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def fuzz_parameters(self, base_url: str) -> dict:
        """Fuzzing de parámetros GET."""
        console.print(f"\n  [module]ffuf params[/] → {base_url}")

        wl_path = find_wordlist(
            "parameters",
            self.cfg.get("wordlists", {}).get("parameters", "")
        )
        if not wl_path:
            log.warning("[warning]Wordlist de parámetros no encontrada[/]")
            return {"error": "wordlist not found", "results": []}

        url = base_url.rstrip("/") + "?FUZZ=1"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        try:
            # Filtrar respuestas con mismo tamaño que base
            cmd = self._build_base_cmd(url, wl_path, out_path)
            rc, stdout, stderr = run_cmd(cmd, timeout=300)
            results = parse_ffuf_output(out_path)

            console.print(f"  [success]✓[/] Params: [bold]{len(results)}[/] parámetros encontrados")
            return {"mode": "parameters", "url": url, "results": results}

        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def fuzz_vhosts(self, base_url: str, domain: str) -> dict:
        """Fuzzing de virtual hosts."""
        console.print(f"\n  [module]ffuf vhosts[/] → {base_url}")

        wl_path = find_wordlist(
            "vhosts",
            self.cfg.get("wordlists", {}).get("vhosts", "")
        )
        if not wl_path:
            log.warning("[warning]Wordlist de vhosts no encontrada[/]")
            return {"error": "wordlist not found", "results": []}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        try:
            cmd = self._build_base_cmd(
                base_url,
                f"{wl_path}:{domain}",
                out_path,
                extra_flags=["-H", f"Host: FUZZ.{domain}"],
            )
            rc, stdout, stderr = run_cmd(cmd, timeout=300)
            results = parse_ffuf_output(out_path)

            for r in results:
                vhost = r.get("input", {}).get("FUZZ", "")
                if vhost:
                    self.storage.add_finding(
                        title=f"VHost descubierto: {vhost}.{domain}",
                        severity="info",
                        module=self.MODULE_NAME,
                        description=f"Virtual host encontrado vía fuzzing",
                        host=base_url,
                        evidence=f"Status: {r['status']} | Host: {vhost}.{domain}",
                        tags=["fuzzing", "vhost"],
                    )

            console.print(f"  [success]✓[/] VHosts: [bold]{len(results)}[/] encontrados")
            return {"mode": "vhosts", "url": base_url, "results": results}

        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def run(self, targets: list[str], modes: list[str] | None = None, domain: str = "") -> dict:
        if not self.available:
            log.warning(
                "[warning]ffuf no encontrado.[/] "
                "Instala: go install github.com/ffuf/ffuf/v2@latest"
            )
            return {"error": "ffuf not found"}

        console.rule("[module] FUZZING (ffuf) [/]")
        modes = modes or ["directories"]

        all_results = {}

        for target in targets:
            target_results = {}

            if "directories" in modes:
                target_results["directories"] = self.fuzz_directories(target)

            if "parameters" in modes:
                target_results["parameters"] = self.fuzz_parameters(target)

            if "vhosts" in modes and domain:
                target_results["vhosts"] = self.fuzz_vhosts(target, domain)

            all_results[target] = target_results

        self.storage.save_module(self.MODULE_NAME, all_results)
        return all_results
