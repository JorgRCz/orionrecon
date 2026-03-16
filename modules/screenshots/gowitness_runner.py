"""
Wrapper para gowitness — screenshots de URLs.
Captura el aspecto visual de cada URL para incluirlo en el reporte.
Si gowitness no está, intenta con aquatone.
"""
import os
import json
import tempfile
from pathlib import Path
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("screenshots.gowitness")


class GoWitnessRunner:
    MODULE_NAME = "screenshots"
    TOOL = "gowitness"

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("screenshots", {})
        self.available_gowitness = check_tool("gowitness")
        self.available_aquatone  = check_tool("aquatone")

    def run(self, urls: list[str]) -> dict:
        """
        Captura screenshots de las URLs.
        Guarda imágenes en session_path/screenshots/.
        Retorna lista de {url, screenshot_path, status}.
        """
        if not urls:
            return {"screenshots": [], "total": 0}

        # Crear directorio de screenshots
        screenshots_dir = self.storage.session_path / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        results = []

        if self.available_gowitness:
            results = self._run_gowitness(urls, screenshots_dir)
        elif self.available_aquatone:
            results = self._run_aquatone(urls, screenshots_dir)
        else:
            log.info("gowitness y aquatone no disponibles. Screenshots omitidos.")
            return {"screenshots": [], "total": 0, "skipped": True}

        result = {"screenshots": results, "total": len(results)}
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] Screenshots: [bold]{len(results)}[/] capturas tomadas"
        )
        return result

    def _run_gowitness(self, urls: list[str], output_dir: Path) -> list[dict]:
        """Ejecuta gowitness scan file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            urls_file = os.path.join(tmpdir, "urls.txt")
            with open(urls_file, "w") as f:
                f.write("\n".join(urls))

            cmd = [
                "gowitness",
                "scan",
                "file",
                "-f", urls_file,
                "--screenshot-path", str(output_dir),
                "--no-prompt",
            ]

            console.print(f"  [module]gowitness[/] → {len(urls)} URLs")
            rc, stdout, stderr = run_cmd(cmd, timeout=600)

            # Recolectar screenshots generados
            results = []
            for img in sorted(output_dir.glob("*.png")):
                # gowitness nombra los screenshots como hash/url-encoded-filename.png
                results.append({
                    "url":             self._filename_to_url(img.name, urls),
                    "screenshot_path": str(img),
                    "status":          "captured",
                })

            return results

    def _run_aquatone(self, urls: list[str], output_dir: Path) -> list[dict]:
        """Fallback con aquatone."""
        with tempfile.TemporaryDirectory() as tmpdir:
            urls_file = os.path.join(tmpdir, "urls.txt")
            with open(urls_file, "w") as f:
                f.write("\n".join(urls))

            cmd = f"cat {urls_file} | aquatone -out {output_dir} -silent"
            console.print(f"  [module]aquatone[/] → {len(urls)} URLs")
            rc, stdout, stderr = run_cmd(cmd, timeout=600)

            results = []
            # aquatone genera screenshots/ sub-directorio con PNGs
            screenshots_subdir = output_dir / "screenshots"
            if screenshots_subdir.exists():
                for img in sorted(screenshots_subdir.glob("*.png")):
                    results.append({
                        "url":             img.stem,
                        "screenshot_path": str(img),
                        "status":          "captured",
                    })
            # También en raíz
            for img in sorted(output_dir.glob("*.png")):
                results.append({
                    "url":             img.stem,
                    "screenshot_path": str(img),
                    "status":          "captured",
                })

            return results

    def _filename_to_url(self, filename: str, urls: list[str]) -> str:
        """Intenta mapear un nombre de archivo de screenshot a su URL original."""
        # gowitness usa el hostname como parte del nombre
        stem = Path(filename).stem.lower()
        for url in urls:
            host = url.replace("https://", "").replace("http://", "").split("/")[0].lower()
            if host in stem or stem.startswith(host.replace(".", "_")):
                return url
        return filename
