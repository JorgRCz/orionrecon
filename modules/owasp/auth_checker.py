"""
OWASP A07:2021 — Identification and Authentication Failures

Comprueba:
  · Default credentials en paneles de administración conocidos
  · JWT alg:none / weak secret detection en respuestas
  · HTTP Basic Auth expuesto sin HTTPS
  · Interfaces admin accesibles sin autenticación
"""
from __future__ import annotations
import re
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("owasp.auth")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _OK = True
except ImportError:
    _OK = False

MODULE_NAME = "auth_check"

# ── Paneles conocidos con sus rutas y credenciales por defecto ─────────────
# Formato: (path, service_name, [(user, pass), ...], marker_en_200_ok)
_PANELS: list[tuple[str, str, list[tuple[str, str]], str]] = [
    # Jenkins
    ("/login",        "Jenkins",    [("admin", "admin"), ("admin", "password"), ("admin", "jenkins")],
     "Jenkins"),
    # Tomcat Manager
    ("/manager/html", "Tomcat",     [("admin", "admin"), ("tomcat", "tomcat"), ("manager", "manager"), ("admin", "tomcat")],
     "Apache Tomcat"),
    # phpMyAdmin
    ("/phpmyadmin/",  "phpMyAdmin", [("root", ""), ("root", "root"), ("admin", "admin"), ("pma", "pma")],
     "phpMyAdmin"),
    ("/pma/",         "phpMyAdmin", [("root", ""), ("root", "root")],
     "phpMyAdmin"),
    # Grafana
    ("/login",        "Grafana",    [("admin", "admin"), ("admin", "grafana")],
     "Grafana"),
    # Kibana / Elasticsearch
    ("/app/kibana",   "Kibana",     [("elastic", "elastic"), ("kibana", "kibana"), ("admin", "admin")],
     "Kibana"),
    # RabbitMQ
    ("/#/",           "RabbitMQ",   [("guest", "guest"), ("admin", "admin")],
     "RabbitMQ"),
    # Jupyter
    ("/tree",         "Jupyter",    [],   # sin creds — acceso abierto
     "Jupyter"),
    # Adminer
    ("/adminer",      "Adminer",    [("root", ""), ("admin", "admin")],
     "Adminer"),
    ("/adminer.php",  "Adminer",    [("root", ""), ("admin", "admin")],
     "Adminer"),
    # WordPress
    ("/wp-login.php", "WordPress",  [("admin", "admin"), ("admin", "password"), ("admin", "wordpress")],
     "WordPress"),
    # Drupal
    ("/user/login",   "Drupal",     [("admin", "admin"), ("admin", "drupal")],
     "Drupal"),
    # GitLab
    ("/users/sign_in","GitLab",     [("root", "5iveL!fe"), ("root", "password"), ("admin", "admin")],
     "GitLab"),
    # Portainer
    ("/",             "Portainer",  [("admin", "admin"), ("admin", "portainer")],
     "Portainer"),
    # SonarQube
    ("/sessions/new", "SonarQube",  [("admin", "admin"), ("sonar", "sonar")],
     "SonarQube"),
    # Webmin
    (":10000/",       "Webmin",     [("root", "root"), ("admin", "admin")],
     "Webmin"),
]

# Cabeceras para los intentos de login
_UA = {"User-Agent": "Mozilla/5.0 OrionRecon/1.0"}


class AuthChecker:
    MODULE_NAME = MODULE_NAME
    DELAY       = 0.3   # delay entre intentos para no bloquear
    TIMEOUT     = 10

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
        self.storage = storage
        self.cfg     = config.get("owasp", {}).get("auth", {})
        self.timeout = self.cfg.get("timeout", self.TIMEOUT)

    def run(self, http_targets: list[str], storage_data: dict | None = None) -> dict:
        if not _OK:
            log.warning("requests no disponible para AuthChecker")
            return {"default_creds": [], "jwt_issues": [], "open_panels": [], "total_tested": 0}

        console.rule("[module] OWASP A07 — Auth & Default Credentials [/]")

        # Extraer hosts base de los targets
        hosts = []
        for t in http_targets:
            t = t.replace("https://", "").replace("http://", "").rstrip("/")
            if t and t not in hosts:
                hosts.append(t)

        console.print(f"  [module]AuthChecker[/] → {len(hosts)} hosts")

        open_panels:   list[dict] = []
        default_creds: list[dict] = []
        jwt_issues:    list[dict] = []

        # 1. Buscar paneles abiertos y probar default credentials
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                ex.submit(self._check_host, host): host
                for host in hosts[:30]
            }
            for fut in as_completed(futures):
                host = futures[fut]
                try:
                    r = fut.result()
                    open_panels.extend(r.get("open_panels", []))
                    default_creds.extend(r.get("default_creds", []))
                except Exception as e:
                    log.debug(f"AuthChecker error {host}: {e}")

        # 2. Buscar JWTs en respuestas y verificar problemas
        jwt_issues = self._check_jwt_in_responses(http_targets[:15], storage_data or {})

        # Generar findings
        for p in open_panels:
            self._add_finding_open_panel(p)
        for c in default_creds:
            self._add_finding_default_cred(c)
        for j in jwt_issues:
            self._add_finding_jwt(j)

        result = {
            "open_panels":   open_panels,
            "default_creds": default_creds,
            "jwt_issues":    jwt_issues,
            "total_tested":  len(hosts),
        }
        self.storage.save_module(self.MODULE_NAME, result)

        console.print(
            f"  [success]✓[/] Auth: "
            f"[bold]{len(open_panels)}[/] paneles abiertos · "
            f"[bold]{len(default_creds)}[/] default creds · "
            f"[bold]{len(jwt_issues)}[/] JWT issues"
        )
        return result

    # ── Check por host ────────────────────────────────────────────────────────

    def _check_host(self, host: str) -> dict:
        open_panels: list[dict]   = []
        default_creds: list[dict] = []
        seen_services: set[str]   = set()

        for scheme in ("https", "http"):
            base_url = f"{scheme}://{host}"

            for path, service, creds, marker in _PANELS:
                # Evitar duplicar el mismo servicio en http y https
                svc_key = f"{host}|{service}|{path}"
                if svc_key in seen_services:
                    continue

                # Construir URL del panel
                if ":" in path and path.startswith(":"):
                    # Port-based (ej. :10000/)
                    port_path = path.lstrip(":")
                    parts = port_path.split("/", 1)
                    panel_url = f"{scheme}://{host}:{parts[0]}/{parts[1] if len(parts) > 1 else ''}"
                else:
                    panel_url = base_url + path

                try:
                    r = requests.get(
                        panel_url, timeout=self.timeout, verify=False,
                        allow_redirects=True, headers=_UA,
                    )
                except Exception as e:
                    log.debug(f"Panel check error {panel_url}: {e}")
                    continue

                # ¿El panel existe y muestra el marker esperado?
                panel_accessible = (
                    r.status_code in (200, 401, 403)
                    and (not marker or marker.lower() in r.text.lower())
                )
                if not panel_accessible:
                    continue

                seen_services.add(svc_key)

                # Jupyter sin password — acceso completamente abierto
                if service == "Jupyter" and r.status_code == 200 and "Jupyter" in r.text:
                    open_panels.append({
                        "host":    host,
                        "url":     panel_url,
                        "service": service,
                        "reason":  "Jupyter Notebook accesible sin autenticación",
                    })
                    continue

                # HTTP Basic Auth expuesto
                if r.status_code == 401 and "www-authenticate" in {k.lower() for k in r.headers}:
                    basic = r.headers.get("WWW-Authenticate", "")
                    if "basic" in basic.lower():
                        open_panels.append({
                            "host":    host,
                            "url":     panel_url,
                            "service": service,
                            "reason":  f"HTTP Basic Auth expuesto: {basic}",
                        })

                # Intentar default creds
                for user, passwd in creds[:4]:  # máximo 4 pares por panel
                    time.sleep(self.DELAY)
                    success = self._try_login(service, panel_url, user, passwd, r)
                    if success:
                        default_creds.append({
                            "host":     host,
                            "url":      panel_url,
                            "service":  service,
                            "username": user,
                            "password": passwd,
                        })
                        break  # con un éxito basta

            # Si encontramos cosas en https, no necesitamos probar http para los mismos paths
            if open_panels or default_creds:
                break

        return {"open_panels": open_panels, "default_creds": default_creds}

    def _try_login(
        self, service: str, panel_url: str,
        user: str, passwd: str, login_page_resp: "requests.Response",
    ) -> bool:
        """Intenta autenticarse y retorna True si tuvo éxito."""
        try:
            if service in ("Tomcat",):
                # HTTP Basic Auth
                r = requests.get(
                    panel_url, timeout=self.timeout, verify=False,
                    auth=(user, passwd), headers=_UA,
                )
                return r.status_code == 200 and "Manager" in r.text

            elif service == "Jenkins":
                # Form-based: POST /j_spring_security_check
                base = panel_url.rsplit("/login", 1)[0]
                r = requests.post(
                    f"{base}/j_spring_security_check",
                    data={"j_username": user, "j_password": passwd, "Submit": "Sign in"},
                    timeout=self.timeout, verify=False, allow_redirects=True, headers=_UA,
                )
                return r.status_code == 200 and "/login" not in r.url and "loginError" not in r.text

            elif service == "phpMyAdmin":
                r = requests.post(
                    panel_url,
                    data={"pma_username": user, "pma_password": passwd, "server": "1"},
                    timeout=self.timeout, verify=False, allow_redirects=True, headers=_UA,
                )
                return "logout" in r.url or "db_structure" in r.text or "main.php" in r.text

            elif service == "Grafana":
                base = panel_url.rsplit("/login", 1)[0]
                r = requests.post(
                    f"{base}/api/login",
                    json={"user": user, "password": passwd},
                    timeout=self.timeout, verify=False, headers=_UA,
                )
                return r.status_code == 200 and "logged" in r.text.lower()

            elif service == "WordPress":
                r = requests.post(
                    panel_url,
                    data={"log": user, "pwd": passwd, "wp-submit": "Log+In",
                          "redirect_to": "/wp-admin/", "testcookie": "1"},
                    timeout=self.timeout, verify=False, allow_redirects=True, headers=_UA,
                )
                return "dashboard" in r.url or "wp-admin" in r.url

            elif service == "GitLab":
                # Obtener CSRF token
                csrf = ""
                m = re.search(r'name="authenticity_token"[^>]+value="([^"]+)"',
                               login_page_resp.text)
                if m:
                    csrf = m.group(1)
                r = requests.post(
                    panel_url,
                    data={"user[login]": user, "user[password]": passwd,
                          "authenticity_token": csrf},
                    timeout=self.timeout, verify=False, allow_redirects=True, headers=_UA,
                )
                return r.status_code == 200 and "sign_out" in r.text

            else:
                # Genérico: HTTP Basic
                r = requests.get(
                    panel_url, timeout=self.timeout, verify=False,
                    auth=(user, passwd), headers=_UA,
                )
                return r.status_code == 200

        except Exception:
            return False

    # ── JWT checks ────────────────────────────────────────────────────────────

    def _check_jwt_in_responses(self, urls: list[str], storage_data: dict) -> list[dict]:
        """
        Busca JWTs en cookies y headers de respuesta.
        Comprueba: alg:none, alg:HS256 con secret débil, expiración.
        """
        issues: list[dict] = []
        seen_jwts: set[str] = set()

        _JWT_RE = re.compile(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        )

        for url in urls:
            try:
                r = requests.get(
                    url, timeout=self.timeout, verify=False,
                    allow_redirects=True, headers=_UA,
                )
            except Exception as e:
                log.debug(f"JWT scan error {url}: {e}")
                continue

            host = re.sub(r"https?://", "", url).split("/")[0]

            # Buscar JWTs en cookies y en el body
            sources: list[str] = []
            for cookie_val in r.cookies.values():
                sources.append(cookie_val)
            sources.append(r.text[:5000])  # primeros 5KB del body

            for source in sources:
                for jwt_token in _JWT_RE.findall(source):
                    if jwt_token in seen_jwts:
                        continue
                    seen_jwts.add(jwt_token)

                    issue = self._analyze_jwt(jwt_token, host, url)
                    if issue:
                        issues.append(issue)

        return issues

    def _analyze_jwt(self, token: str, host: str, url: str) -> dict | None:
        """Analiza un JWT para detectar problemas de seguridad."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decodificar header y payload (base64url)
            def _b64_decode(s: str) -> dict:
                s += "=" * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", errors="replace"))

            header  = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])

            alg = header.get("alg", "").upper()

            # alg:none — sin firma
            if alg in ("NONE", ""):
                return {
                    "host":    host,
                    "url":     url,
                    "issue":   "JWT con alg:none — sin verificación de firma",
                    "severity": "critical",
                    "detail":  f"Header: {header}\nPayload: {payload}",
                    "token":   token[:60] + "…",
                }

            # alg:HS256 — podría ser brute-forceable, reportar como info
            if alg in ("HS256", "HS384", "HS512"):
                weak_secrets = ["secret", "password", "123456", "jwt", "key",
                                 "changeme", "supersecret", "test", "admin"]
                # Intentar verificar con secrets débiles
                try:
                    import hmac
                    import hashlib
                    msg = f"{parts[0]}.{parts[1]}".encode()
                    sig = base64.urlsafe_b64decode(parts[2] + "==")
                    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                                 "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
                    for secret in weak_secrets:
                        expected = hmac.new(secret.encode(), msg, hash_func).digest()
                        if hmac.compare_digest(expected, sig):
                            return {
                                "host":     host,
                                "url":      url,
                                "issue":    f"JWT firmado con secret débil: '{secret}'",
                                "severity": "critical",
                                "detail":   f"Algorithm: {alg}\nSecret: {secret}",
                                "token":    token[:60] + "…",
                            }
                except Exception as e:
                    log.debug(f"JWT HMAC brute-force error: {e}")

            # Sin expiración (no exp claim)
            if "exp" not in payload:
                return {
                    "host":    host,
                    "url":     url,
                    "issue":   "JWT sin claim 'exp' — token no expira",
                    "severity": "medium",
                    "detail":  f"Payload: {list(payload.keys())}",
                    "token":   token[:60] + "…",
                }

            return None

        except Exception:
            return None

    # ── Findings ──────────────────────────────────────────────────────────────

    def _add_finding_open_panel(self, p: dict):
        self.storage.add_finding(
            title=f"Panel admin accesible: {p['service']} en {p['host']}",
            severity="high",
            module=self.MODULE_NAME,
            description=(
                f"Panel de administración {p['service']} encontrado en {p['url']}. "
                f"Razón: {p['reason']}"
            ),
            host=p["host"],
            url=p["url"],
            evidence=p["reason"],
            tags=["admin-panel", "A07", p["service"].lower()],
        )

    def _add_finding_default_cred(self, c: dict):
        self.storage.add_finding(
            title=f"Default credentials válidas: {c['service']} en {c['host']} ({c['username']}:{c['password']})",
            severity="critical",
            module=self.MODULE_NAME,
            description=(
                f"Acceso exitoso con credenciales por defecto en {c['service']} ({c['url']}). "
                f"Usuario: {c['username']} / Contraseña: {c['password']}. "
                f"Un atacante puede tomar control total del panel."
            ),
            host=c["host"],
            url=c["url"],
            evidence=f"Usuario: {c['username']}\nContraseña: {c['password']}\nServicio: {c['service']}",
            tags=["default-credentials", "A07", c["service"].lower(), "authentication"],
        )

    def _add_finding_jwt(self, j: dict):
        self.storage.add_finding(
            title=f"JWT inseguro: {j['issue']} en {j['host']}",
            severity=j["severity"],
            module=self.MODULE_NAME,
            description=(
                f"Se detectó un JSON Web Token con problemas de seguridad en {j['url']}. "
                f"Problema: {j['issue']}"
            ),
            host=j["host"],
            url=j["url"],
            evidence=f"{j['detail']}\nToken: {j['token']}",
            tags=["jwt", "A07", "authentication", "token"],
        )
