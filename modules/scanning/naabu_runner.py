"""
Wrapper para naabu (ProjectDiscovery) — port scanner rápido.
Hace descubrimiento rápido de puertos ANTES del nmap profundo.
"""
import json
import tempfile
import os
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("scanning.naabu")


class NaabuRunner:
    MODULE_NAME = "naabu"
    TOOL = "naabu"

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("scanning", {}).get("naabu", {})
        self.available = check_tool(self.TOOL)

    def run(self, hosts: list[str]) -> dict:
        """
        Descubre puertos abiertos en la lista de hosts.
        Retorna dict {host: [ports]}.
        """
        if not self.available:
            log.debug("naabu no disponible, saltando")
            return {"hosts": {}, "total_ports": 0}

        if not hosts:
            return {"hosts": {}, "total_ports": 0}

        results = self._run_naabu(hosts)

        total_ports = sum(len(p) for p in results.values())
        self.storage.save_module(self.MODULE_NAME, {
            "hosts": results,
            "total_ports": total_ports,
        })

        console.print(
            f"  [success]✓[/] naabu: [bold]{len(results)}[/] hosts, "
            f"[bold]{total_ports}[/] puertos abiertos"
        )
        return {"hosts": results, "total_ports": total_ports}

    def _run_naabu(self, hosts: list[str]) -> dict:
        """Ejecuta naabu y parsea el output JSONL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = os.path.join(tmpdir, "hosts.txt")
            out_file   = os.path.join(tmpdir, "naabu_out.json")

            # Escribir hosts (sin schema)
            clean_hosts = []
            for h in hosts:
                h = h.replace("https://", "").replace("http://", "").split("/")[0].strip()
                if h and h not in clean_hosts:
                    clean_hosts.append(h)

            with open(hosts_file, "w") as f:
                f.write("\n".join(clean_hosts))

            top_ports = self.cfg.get("top_ports", 1000)
            cmd = [
                "naabu",
                "-l",        hosts_file,
                "-top-ports", str(top_ports),
                "-silent",
                "-json",
                "-o",        out_file,
            ]

            console.print(f"  [module]naabu[/] → {len(clean_hosts)} hosts (top-{top_ports})")
            rc, stdout, stderr = run_cmd(cmd, timeout=600)

            results: dict[str, list[int]] = {}

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
                    host  = entry.get("host") or entry.get("ip", "")
                    port  = entry.get("port", 0)
                    if host and port:
                        if host not in results:
                            results[host] = []
                        if port not in results[host]:
                            results[host].append(port)
                except json.JSONDecodeError:
                    # Algunos formatos son "host:port"
                    if ":" in line:
                        parts = line.rsplit(":", 1)
                        try:
                            host = parts[0]
                            port = int(parts[1])
                            if host not in results:
                                results[host] = []
                            if port not in results[host]:
                                results[host].append(port)
                        except (ValueError, IndexError):
                            pass

            # Ordenar puertos
            for host in results:
                results[host] = sorted(results[host])

            return results
