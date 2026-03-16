"""
Wrapper para asnmap (ProjectDiscovery) — descubrimiento de rangos IP por ASN.
Identifica los CIDRs asociados al dominio objetivo para ampliar el scope.
"""
import re
import tempfile
import os
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger

log = get_logger("recon.asnmap")

# Regex para CIDRs IPv4
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
# Regex para ASN
_ASN_RE  = re.compile(r"\bAS\d+\b", re.IGNORECASE)


class AsnmapRunner:
    NAME = "asnmap"
    TOOL = "asnmap"

    def __init__(self, config: dict):
        self.cfg = config.get("recon", {}).get("asnmap", {})
        self.available = check_tool(self.TOOL)

    def run(self, domain: str) -> dict:
        """
        Descubre rangos IP (CIDRs) asociados al ASN del dominio.
        Retorna dict con cidrs, asn_info y método usado.
        """
        if self.available:
            return self._run_asnmap(domain)
        else:
            log.debug("asnmap no disponible, usando fallback whois")
            return self._run_whois_fallback(domain)

    def _run_asnmap(self, domain: str) -> dict:
        cmd = [
            "asnmap",
            "-d", domain,
            "-silent",
        ]
        console.print(f"  [module]asnmap[/] → {domain}")
        rc, stdout, stderr = run_cmd(cmd, timeout=120)

        cidrs = []
        asns  = []
        for line in stdout.splitlines():
            line = line.strip()
            for cidr in _CIDR_RE.findall(line):
                if cidr not in cidrs:
                    cidrs.append(cidr)
            for asn in _ASN_RE.findall(line):
                asn_upper = asn.upper()
                if asn_upper not in asns:
                    asns.append(asn_upper)

        console.print(
            f"  [success]✓[/] asnmap: [bold]{len(cidrs)}[/] CIDRs, "
            f"[bold]{len(asns)}[/] ASNs"
        )
        return {
            "cidrs":  cidrs,
            "asns":   asns,
            "method": "asnmap",
        }

    def _run_whois_fallback(self, domain: str) -> dict:
        """Fallback básico usando whois para extraer CIDRs."""
        if not check_tool("whois"):
            return {"cidrs": [], "asns": [], "method": "none"}

        # Primero resolvemos el dominio para obtener una IP
        try:
            import socket
            ip = socket.gethostbyname(domain)
        except Exception:
            return {"cidrs": [], "asns": [], "method": "none"}

        rc, stdout, stderr = run_cmd(["whois", ip], timeout=60)

        cidrs = []
        asns  = []
        for line in (stdout + stderr).splitlines():
            for cidr in _CIDR_RE.findall(line):
                if cidr not in cidrs:
                    cidrs.append(cidr)
            for asn in _ASN_RE.findall(line):
                asn_upper = asn.upper()
                if asn_upper not in asns:
                    asns.append(asn_upper)

        if cidrs or asns:
            console.print(
                f"  [success]✓[/] whois fallback: [bold]{len(cidrs)}[/] CIDRs"
            )

        return {
            "cidrs":  cidrs,
            "asns":   asns,
            "method": "whois",
        }
