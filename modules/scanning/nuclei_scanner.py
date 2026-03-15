"""
Nuclei scanner — detección de vulnerabilidades con templates.
"""
import json
import tempfile
import os
from modules.core.engine import run_cmd, check_tool
from modules.core.logger import console, get_logger, sev_badge
from modules.core.storage import Storage

log = get_logger("scanning.nuclei")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class NucleiScanner:
    MODULE_NAME = "nuclei"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.cfg = config.get("nuclei", {})
        self.available = check_tool("nuclei")

    def update_templates(self):
        """Actualiza los templates de nuclei."""
        if not self.available:
            return
        console.print("[module]nuclei[/] actualizando templates...")
        rc, stdout, stderr = run_cmd("nuclei -update-templates", timeout=120)
        if rc == 0:
            console.print("[success]✓[/] Templates actualizados")
        else:
            log.warning(f"Error actualizando templates: {stderr[:200]}")

    def run(self, targets: list[str], extra_tags: list[str] | None = None) -> dict:
        if not self.available:
            log.warning(
                "[warning]nuclei no encontrado.[/] "
                "Instala: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
            return {"error": "nuclei not found", "findings": []}

        console.rule("[module] NUCLEI SCANNER [/]")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as out_file:
            out_path = out_file.name

        try:
            severity = ",".join(self.cfg.get("severity", ["critical", "high", "medium"]))
            rate_limit = self.cfg.get("rate_limit", 150)
            bulk_size = self.cfg.get("bulk_size", 25)
            concurrency = self.cfg.get("concurrency", 10)

            cmd = [
                "nuclei",
                "-l", targets_path,
                "-s", severity,
                "-rl", str(rate_limit),
                "-bs", str(bulk_size),
                "-c", str(concurrency),
                "-json",
                "-o", out_path,
                "-silent",
            ]

            # Tags adicionales
            all_tags = self.cfg.get("tags", []) + (extra_tags or [])
            if all_tags:
                cmd += ["-tags", ",".join(all_tags)]

            console.print(f"  Targets    : [bold]{len(targets)}[/]")
            console.print(f"  Severidades: [bold]{severity}[/]")
            console.print(f"  Rate limit : [bold]{rate_limit} req/s[/]")

            rc, stdout, stderr = run_cmd(cmd, timeout=1800)  # 30 min timeout

            findings = []
            if os.path.exists(out_path):
                with open(out_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            pass

            # Procesar findings y guardar
            for finding in findings:
                sev = finding.get("info", {}).get("severity", "info").lower()
                name = finding.get("info", {}).get("name", "Unknown")
                template_id = finding.get("template-id", "")
                matched_at = finding.get("matched-at", "")
                host = finding.get("host", "")
                cve = ""

                # Extraer CVE si existe
                classification = finding.get("info", {}).get("classification", {})
                cves = classification.get("cve-id", [])
                if cves:
                    cve = cves[0] if isinstance(cves, list) else cves

                description = finding.get("info", {}).get("description", "")
                remediation = finding.get("info", {}).get("remediation", "")

                self.storage.add_finding(
                    title=f"[{template_id}] {name}",
                    severity=sev,
                    module=self.MODULE_NAME,
                    description=description,
                    host=host,
                    url=matched_at,
                    evidence=str(finding.get("extracted-results", ""))[:500],
                    cve=cve,
                    tags=["nuclei", template_id, sev],
                )

                badge = sev_badge(sev)
                console.print(f"  {badge} {name} → {matched_at}")

            result = {
                "total": len(findings),
                "by_severity": {
                    sev: sum(
                        1 for f in findings
                        if f.get("info", {}).get("severity", "").lower() == sev
                    )
                    for sev in SEVERITY_ORDER
                },
                "findings": findings,
            }

            self.storage.save_module(self.MODULE_NAME, result)

            console.print(f"\n[success]✓ Nuclei:[/] {len(findings)} findings")
            for sev in SEVERITY_ORDER:
                count = result["by_severity"][sev]
                if count:
                    console.print(f"  {sev_badge(sev)} {count}")

            return result

        finally:
            for f in [targets_path, out_path]:
                if os.path.exists(f):
                    os.unlink(f)
