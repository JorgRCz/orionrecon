"""
Session storage: persiste todos los resultados en JSON por sesión.
"""
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from modules.core.repro import generate_repro_steps


class Storage:
    def __init__(self, session_dir: str, target: str):
        self.target = target
        self.session_dir = Path(session_dir)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        self.session_path = self.session_dir / f"{safe_target}_{timestamp}"
        self.session_path.mkdir(parents=True, exist_ok=True)

        self.data: dict[str, Any] = {
            "meta": {
                "target": target,
                "started_at": datetime.now().isoformat(),
                "finished_at": None,
                "session_dir": str(self.session_path),
            },
            "findings": [],
            "modules": {},
        }
        self._save()

    def save_module(self, module: str, results: Any):
        self.data["modules"][module] = {
            "timestamp": datetime.now().isoformat(),
            "results": results,
        }
        self._save()

    def add_finding(
        self,
        title: str,
        severity: str,
        module: str,
        description: str = "",
        host: str = "",
        url: str = "",
        evidence: str = "",
        cve: str = "",
        tags: list[str] | None = None,
    ):
        finding = {
            "id": len(self.data["findings"]) + 1,
            "title": title,
            "severity": severity.lower(),
            "module": module,
            "description": description,
            "host": host,
            "url": url,
            "evidence": evidence,
            "cve": cve,
            "tags": tags or [],
            "timestamp": datetime.now().isoformat(),
        }
        finding["repro"] = generate_repro_steps(finding)
        self.data["findings"].append(finding)
        self._save()
        return finding

    def finish(self):
        self.data["meta"]["finished_at"] = datetime.now().isoformat()
        self._save()

    def _save(self):
        out = self.session_path / "results.json"
        with open(out, "w") as f:
            json.dump(self.data, f, indent=2, default=str)

    def get_findings_by_severity(self) -> dict[str, list]:
        result: dict[str, list] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in self.data["findings"]:
            sev = f.get("severity", "info")
            if sev in result:
                result[sev].append(f)
        return result

    def summary(self) -> dict:
        by_sev = self.get_findings_by_severity()
        return {
            "total": len(self.data["findings"]),
            "critical": len(by_sev["critical"]),
            "high": len(by_sev["high"]),
            "medium": len(by_sev["medium"]),
            "low": len(by_sev["low"]),
            "info": len(by_sev["info"]),
            "modules_run": list(self.data["modules"].keys()),
        }
