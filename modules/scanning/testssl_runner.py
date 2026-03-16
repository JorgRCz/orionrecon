"""
TLS/SSL Scanner — usa sslscan como primario, testssl.sh como secundario,
fallback Python básico.

sslscan  : rápido, XML output, ideal para automatización
testssl.sh: más completo, más CVEs, recomendado para análisis profundo
"""
import json
import ssl
import socket
import tempfile
import os
import xml.etree.ElementTree as ET
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("scanning.tls")

_WEAK_PROTOS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1"}

_KNOWN_VULNS = [
    "BEAST", "POODLE", "DROWN", "LOGJAM", "FREAK",
    "Heartbleed", "CCS", "LUCKY13", "SWEET32", "ROBOT", "BREACH", "CRIME",
]


class TestsslRunner:
    MODULE_NAME = "tls_ssl"

    def __init__(self, config: dict, storage: Storage):
        self.config   = config
        self.storage  = storage
        self.cfg      = config.get("scanning", {}).get("tls", {})
        self.sslscan  = check_tool("sslscan")
        self.testssl  = check_tool("testssl.sh") or check_tool("testssl")

    def run(self, targets: list[str]) -> dict:
        console.rule("[module] TLS/SSL SCANNER [/]")
        tool_used = "sslscan" if self.sslscan else ("testssl.sh" if self.testssl else "python-ssl")
        console.print(f"  [info]Motor:[/] [bold]{tool_used}[/]")

        results = {}

        for target in targets:
            host, port = self._extract_host_port(target)
            key = f"{host}:{port}"
            console.print(f"  [module]TLS[/] → {key}")

            if self.sslscan:
                res = self._run_sslscan(host, port)
            elif self.testssl:
                res = self._run_testssl(host, port)
            else:
                res = self._run_python_fallback(host, port)

            results[key] = res

            # Generar findings
            self._generate_findings(host, port, res)

        self.storage.save_module(self.MODULE_NAME, {"results": results})
        console.print(f"  [success]✓[/] TLS/SSL: {len(results)} targets analizados")
        return {"results": results}

    def _extract_host_port(self, target: str) -> tuple[str, int]:
        """Extrae host y puerto del target."""
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                pass
        return target, 443

    def _run_sslscan(self, host: str, port: int) -> dict:
        """sslscan — rápido, XML output. Primario."""
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            xml_path = f.name

        try:
            cmd = ["sslscan", "--xml=" + xml_path, "--no-colour", f"{host}:{port}"]
            rc, stdout, stderr = run_cmd(cmd, timeout=60)

            if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
                return self._run_python_fallback(host, port)

            return self._parse_sslscan_xml(xml_path)
        except Exception as e:
            log.debug(f"sslscan error {host}:{port}: {e}")
            return self._run_python_fallback(host, port)
        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

    def _parse_sslscan_xml(self, xml_path: str) -> dict:
        """Parsea el XML de sslscan."""
        result = {
            "tool": "sslscan",
            "weak_protocols": [], "weak_ciphers": [],
            "vulnerabilities": [], "cert_info": {}, "issues": [],
        }
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            ssltest = root.find("ssltest") or root

            # Protocolos
            for proto in ssltest.findall("protocol"):
                ptype    = proto.get("type", "")
                pversion = proto.get("version", "")
                enabled  = proto.get("enabled", "0")
                name     = f"{ptype.upper()}v{pversion}" if ptype else pversion
                if enabled == "1" and any(w.lower() in name.lower() for w in ["ssl", "1.0", "1.1"]):
                    result["weak_protocols"].append(name)
                    result["issues"].append({
                        "id": f"proto_{name}", "severity": "medium",
                        "finding": f"Protocolo débil habilitado: {name}",
                    })

            # Heartbleed
            for hb in ssltest.findall("heartbleed"):
                if hb.get("vulnerable", "0") == "1":
                    result["vulnerabilities"].append({
                        "name": "Heartbleed", "severity": "CRITICAL",
                        "finding": f"Heartbleed vulnerable en {hb.get('sslversion','')}",
                    })

            # Cipher suites débiles
            weak_kx = {"RC4", "DES", "3DES", "EXPORT", "NULL", "anon"}
            for cipher in ssltest.findall("cipher"):
                cipher_name = cipher.get("cipher", "")
                status = cipher.get("status", "")
                bits   = int(cipher.get("bits", "128") or "128")
                if any(w in cipher_name.upper() for w in weak_kx) or bits < 128:
                    result["weak_ciphers"].append(cipher_name)
                    result["issues"].append({
                        "id": f"cipher_{cipher_name}", "severity": "medium",
                        "finding": f"Cipher débil: {cipher_name} ({bits} bits)",
                    })

            # Certificado
            cert = ssltest.find("certificate")
            if cert is not None:
                result["cert_info"] = {
                    "subject":    cert.findtext("subject", ""),
                    "issuer":     cert.findtext("issuer", ""),
                    "not_after":  cert.findtext("not-valid-after", cert.findtext("expire", "")),
                    "not_before": cert.findtext("not-valid-before", ""),
                    "signature":  cert.findtext("signature-algorithm", ""),
                }
                # Certificado expirado / autofirmado
                pk_bits = cert.findtext("pk-bits", "")
                if pk_bits and int(pk_bits or "2048") < 2048:
                    result["issues"].append({
                        "id": "weak_key", "severity": "medium",
                        "finding": f"Clave pública débil: {pk_bits} bits",
                    })

        except Exception as e:
            log.debug(f"Error parseando XML sslscan: {e}")

        return result

    def _run_testssl(self, host: str, port: int) -> dict:
        """Ejecuta testssl.sh y parsea el JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "testssl_out.json")
            target   = f"{host}:{port}"

            # Intentar ambos nombres
            tool = "testssl.sh" if check_tool("testssl.sh") else "testssl"
            cmd = [
                tool,
                "--jsonfile", out_file,
                "--severity", "MEDIUM",
                "--quiet",
                "--nodns", "min",
                target,
            ]

            rc, stdout, stderr = run_cmd(cmd, timeout=300)

            if not os.path.exists(out_file):
                log.debug(f"testssl.sh no produjo JSON para {target}")
                return self._run_python_fallback(host, port)

            try:
                with open(out_file, encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except Exception:
                return self._run_python_fallback(host, port)

            return self._parse_testssl_json(data)

    def _parse_testssl_json(self, data: dict | list) -> dict:
        """Parsea el JSON de testssl.sh."""
        # testssl.sh v3 produce un dict con "scanResult" como lista
        scan_results = []
        if isinstance(data, dict):
            scan_results = data.get("scanResult", data.get("results", [data]))
        elif isinstance(data, list):
            scan_results = data

        weak_protocols = []
        weak_ciphers   = []
        vulns          = []
        cert_info      = {}
        issues         = []

        for entry in scan_results:
            if not isinstance(entry, dict):
                continue

            severity = entry.get("severity", "").upper()
            finding  = entry.get("finding", "")
            id_      = entry.get("id", "")

            # Protocolos débiles
            for proto in _WEAK_PROTOS:
                if proto.lower() in id_.lower() and "offered" in finding.lower():
                    weak_protocols.append(proto)

            # Vulnerabilidades conocidas
            for vuln in _KNOWN_VULNS:
                if vuln.lower() in id_.lower():
                    if "vulnerable" in finding.lower() or "VULNERABLE" in finding:
                        vulns.append({
                            "name":    vuln,
                            "finding": finding,
                            "severity": severity,
                        })

            # Información de certificado
            if "cert_" in id_ or "certificate" in id_.lower():
                cert_info[id_] = finding

            # Issues relevantes
            if severity in ("MEDIUM", "HIGH", "CRITICAL", "LOW"):
                issues.append({
                    "id":       id_,
                    "severity": severity.lower(),
                    "finding":  finding,
                })

        return {
            "tool":            "testssl.sh",
            "weak_protocols":  list(set(weak_protocols)),
            "weak_ciphers":    weak_ciphers,
            "vulnerabilities": vulns,
            "cert_info":       cert_info,
            "issues":          issues,
        }

    def _run_python_fallback(self, host: str, port: int) -> dict:
        """Análisis básico TLS usando la librería ssl de Python."""
        result = {
            "tool":            "python-ssl",
            "weak_protocols":  [],
            "weak_ciphers":    [],
            "vulnerabilities": [],
            "cert_info":       {},
            "issues":          [],
        }

        try:
            # Verificar si acepta TLSv1.0
            for proto_name, proto_const in [
                ("TLSv1",   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
            ]:
                if proto_const is None:
                    continue
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    ctx.minimum_version = proto_const
                    ctx.maximum_version = proto_const
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            result["weak_protocols"].append(proto_name)
                            result["issues"].append({
                                "id":       f"proto_{proto_name}",
                                "severity": "medium",
                                "finding":  f"Servidor acepta {proto_name} (protocolo débil)",
                            })
                except Exception:
                    pass

            # Obtener información del certificado
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        proto  = ssock.version()

                        result["cert_info"] = {
                            "subject":  str(cert.get("subject", "")),
                            "issuer":   str(cert.get("issuer", "")),
                            "not_after":  cert.get("notAfter", ""),
                            "not_before": cert.get("notBefore", ""),
                        }
                        result["protocol_used"] = proto
                        result["cipher_used"]   = cipher[0] if cipher else ""
            except ssl.SSLError as e:
                result["issues"].append({
                    "id": "cert_error",
                    "severity": "medium",
                    "finding": f"Error SSL: {e}",
                })
            except Exception:
                pass

        except Exception as e:
            log.debug(f"Python SSL fallback error para {host}:{port}: {e}")

        return result

    def _generate_findings(self, host: str, port: int, result: dict):
        """Genera findings en storage basados en el análisis TLS."""
        target_str = f"{host}:{port}"

        for proto in result.get("weak_protocols", []):
            self.storage.add_finding(
                title=f"Protocolo TLS débil: {proto} en {target_str}",
                severity="medium",
                module=self.MODULE_NAME,
                description=f"El servidor {target_str} acepta {proto}, un protocolo considerado inseguro.",
                host=host,
                evidence=f"Protocolo: {proto}",
                tags=["tls", "ssl", "weak-protocol"],
            )

        for vuln in result.get("vulnerabilities", []):
            sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            sev = sev_map.get(vuln.get("severity", "").upper(), "high")
            self.storage.add_finding(
                title=f"TLS Vulnerabilidad: {vuln['name']} en {target_str}",
                severity=sev,
                module=self.MODULE_NAME,
                description=f"Vulnerabilidad {vuln['name']} detectada en {target_str}",
                host=host,
                evidence=vuln.get("finding", ""),
                tags=["tls", "ssl", vuln["name"].lower()],
            )

        for issue in result.get("issues", []):
            if issue.get("severity") in ("critical", "high"):
                self.storage.add_finding(
                    title=f"TLS Issue: {issue.get('id', 'unknown')} en {target_str}",
                    severity=issue["severity"],
                    module=self.MODULE_NAME,
                    description=issue.get("finding", ""),
                    host=host,
                    evidence=issue.get("finding", ""),
                    tags=["tls", "ssl"],
                )
