"""
Nmap Artillery — múltiples perfiles de escaneo con parseo XML de resultados.
"""
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET  # fallback
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage
from rich.table import Table

log = get_logger("scanning.nmap")

# Perfiles de escaneo con descripción y flags
NMAP_PROFILES = {
    "quick":      ("-T4 -F --open",             "100 puertos más comunes"),
    "stealth":    ("-sS -T2 -p- --open -Pn",    "SYN stealth scan full"),
    "full":       ("-sS -sV -sC -O -T4 -p- --open", "Full detección versión + scripts"),
    "vuln":       ("-sV --script=vuln -T4 --open",   "NSE scripts vulnerabilidades"),
    "udp":        ("-sU -T4 --top-ports 200 --open", "UDP top 200 puertos"),
    "aggressive": ("-A -T4 -p- --open",          "Agresivo: OS, versión, traceroute"),
    "web":        ("-sV -p 80,443,8080,8443,8000,8888,3000,4000,5000 --open -sC",
                  "Puertos web comunes"),
    "smb":        ("-p 139,445 --script=smb-vuln* --open", "SMB vulnerabilidades"),
    "ftp":        ("-p 21 --script=ftp-* -sV --open",       "FTP detección"),
    "dns":        ("-p 53 --script=dns-* -sV --open",        "DNS análisis"),
}

# Severidad según tipo de vulnerabilidad
VULN_SEVERITY_MAP = {
    "ms17-010":    "critical",
    "ms08-067":    "critical",
    "heartbleed":  "critical",
    "shellshock":  "critical",
    "eternalblue": "critical",
    "ms12-020":    "high",
    "ms10-054":    "high",
    "smb-vuln":    "high",
    "ssl-poodle":  "medium",
    "ssl-drown":   "medium",
    "anonymous":   "medium",
    "open":        "info",
}


def parse_nmap_xml(xml_content: str) -> dict:
    """Parsea output XML de nmap y retorna estructura limpia."""
    result = {"hosts": [], "open_ports": [], "vulnerabilities": [], "services": {}}

    try:
        root = ET.fromstring(xml_content)

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            # IP/hostname
            ip = ""
            hostnames = []
            address = host.find("address")
            if address is not None:
                ip = address.get("addr", "")

            for hn in host.findall("hostnames/hostname"):
                hostnames.append(hn.get("name", ""))

            os_info = ""
            osmatch = host.find("os/osmatch")
            if osmatch is not None:
                os_info = osmatch.get("name", "")

            ports_info = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    port_num = port.get("portid", "")
                    protocol = port.get("protocol", "tcp")

                    service = port.find("service")
                    svc_name = ""
                    svc_version = ""
                    if service is not None:
                        svc_name = service.get("name", "")
                        product = service.get("product", "")
                        version = service.get("version", "")
                        svc_version = f"{product} {version}".strip()

                    # Scripts NSE
                    scripts_output = []
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        script_out = script.get("output", "")
                        scripts_output.append({
                            "id": script_id,
                            "output": script_out[:500],
                        })

                        # Detectar vulnerabilidades en scripts
                        out_lower = script_out.lower()
                        for vuln_key, sev in VULN_SEVERITY_MAP.items():
                            if vuln_key in script_id.lower() or vuln_key in out_lower:
                                if "VULNERABLE" in script_out or "vulnerable" in out_lower:
                                    result["vulnerabilities"].append({
                                        "host": ip,
                                        "port": port_num,
                                        "protocol": protocol,
                                        "script": script_id,
                                        "severity": sev,
                                        "evidence": script_out[:500],
                                    })

                    port_data = {
                        "port": port_num,
                        "protocol": protocol,
                        "service": svc_name,
                        "version": svc_version,
                        "scripts": scripts_output,
                    }
                    ports_info.append(port_data)
                    result["open_ports"].append(f"{ip}:{port_num}/{protocol}")

            result["hosts"].append({
                "ip": ip,
                "hostnames": hostnames,
                "os": os_info,
                "ports": ports_info,
            })

    except ET.ParseError as e:
        log.error(f"Error parseando XML nmap: {e}")

    return result


class NmapScanner:
    MODULE_NAME = "nmap"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.available = check_tool("nmap")
        self.profiles = config.get("nmap", {}).get("profiles", NMAP_PROFILES)

    def _scan_host(self, host: str, flags: str, profile_name: str) -> dict:
        """Escanea un host con un perfil dado. Usa -oX - (stdout) para
        compatibilidad con nmap instalado via snap (sandbox sin acceso a /tmp)."""
        # -oX - envía el XML a stdout; compatible con nmap snap (sandbox sin /tmp)
        cmd = f"nmap {flags} -oX - {host}"
        rc, xml_content, stderr = run_cmd(cmd, timeout=600)

        if xml_content and xml_content.strip().startswith("<?xml"):
            parsed = parse_nmap_xml(xml_content)
            parsed["raw_xml"] = xml_content[:10000]
        else:
            parsed = {"error": stderr or "No XML output", "hosts": [], "open_ports": []}

        parsed["host"] = host
        parsed["profile"] = profile_name
        parsed["flags"] = flags
        return parsed

    def run(self, targets: list[str], profiles: list[str] | None = None) -> dict:
        if not self.available:
            log.warning("[warning]nmap no encontrado.[/] Instala: sudo apt install nmap")
            return {"error": "nmap not found"}

        selected_profiles = profiles or ["quick"]
        console.rule("[module] NMAP ARTILLERY [/]")
        console.print(f"  Targets  : [bold]{len(targets)}[/]")
        console.print(f"  Perfiles : [bold]{', '.join(selected_profiles)}[/]")

        all_results = {}

        for profile_name in selected_profiles:
            profile_cfg = NMAP_PROFILES.get(profile_name)
            if not profile_cfg:
                log.warning(f"Perfil desconocido: {profile_name}")
                continue

            if isinstance(profile_cfg, tuple):
                flags, desc = profile_cfg
            else:
                flags = profile_cfg.get("flags", "-T4 -F --open")
                desc = profile_cfg.get("description", "")

            console.print(f"\n[module]→ Perfil:[/] [bold]{profile_name}[/] — {desc}")
            console.print(f"  Flags: [dim]{flags}[/]")

            profile_results = []
            max_workers = min(5, len(targets))

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {
                    ex.submit(self._scan_host, host, flags, profile_name): host
                    for host in targets
                }
                for fut in as_completed(futures):
                    host = futures[fut]
                    try:
                        res = fut.result()
                        profile_results.append(res)
                        open_count = len(res.get("open_ports", []))
                        vuln_count = len(res.get("vulnerabilities", []))
                        console.print(
                            f"    [success]✓[/] {host}: "
                            f"[bold]{open_count}[/] puertos abiertos, "
                            f"[bold]{vuln_count}[/] vulns"
                        )
                    except Exception as e:
                        log.error(f"Error escaneando {host}: {e}")

            all_results[profile_name] = profile_results

            # Crear findings desde vulnerabilidades encontradas
            for res in profile_results:
                for vuln in res.get("vulnerabilities", []):
                    self.storage.add_finding(
                        title=f"[{vuln['script']}] en {vuln['host']}:{vuln['port']}",
                        severity=vuln["severity"],
                        module=self.MODULE_NAME,
                        description=f"Script NSE detectó vulnerabilidad: {vuln['script']}",
                        host=vuln["host"],
                        evidence=vuln["evidence"],
                        tags=["nmap", "nse", vuln["script"]],
                    )

                # Findings de puertos de gestión expuestos
                for port_info in res.get("hosts", [{}])[0].get("ports", []) if res.get("hosts") else []:
                    svc = port_info.get("service", "").lower()
                    port = port_info.get("port", "")
                    if svc in ("telnet", "vnc", "rdp", "ftp"):
                        self.storage.add_finding(
                            title=f"Servicio inseguro expuesto: {svc} ({port})",
                            severity="medium",
                            module=self.MODULE_NAME,
                            description=f"El servicio {svc} está accesible en {res['host']}:{port}",
                            host=res["host"],
                            tags=["nmap", "exposure", svc],
                        )

        self.storage.save_module(self.MODULE_NAME, all_results)
        self._print_summary(all_results)
        return all_results

    def _print_summary(self, results: dict):
        table = Table(title="Nmap Results Summary", show_header=True, header_style="bold magenta")
        table.add_column("Host", style="cyan")
        table.add_column("Profile")
        table.add_column("Open Ports", justify="right")
        table.add_column("Vulnerabilities", justify="right")

        for profile, host_results in results.items():
            for res in host_results:
                vuln_count = len(res.get("vulnerabilities", []))
                vuln_style = "red bold" if vuln_count > 0 else "green"
                table.add_row(
                    res.get("host", "?"),
                    profile,
                    str(len(res.get("open_ports", []))),
                    f"[{vuln_style}]{vuln_count}[/]",
                )

        console.print(table)
