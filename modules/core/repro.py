"""
Generador de pasos de reproducción y validación para cada finding.
Los pasos se generan en base al módulo, tags, url y evidencia del finding.
"""
import re
import urllib.parse


def generate_repro_steps(finding: dict) -> list[str]:
    """
    Retorna lista de comandos/pasos para reproducir o validar el finding.
    Cada elemento es un string que puede ser un comando shell o una instrucción.
    """
    module  = (finding.get("module") or "").lower()
    tags    = [t.lower() for t in (finding.get("tags") or [])]
    url     = finding.get("url") or finding.get("host") or ""
    host    = finding.get("host") or ""
    title   = finding.get("title") or ""
    evidence = finding.get("evidence") or ""
    cve     = finding.get("cve") or ""

    # Extraer host limpio (sin esquema)
    host_clean = re.sub(r"https?://", "", host).split("/")[0].split(":")[0]
    url_clean  = url.strip()

    steps = _dispatch(module, tags, url_clean, host_clean, title, evidence, cve)
    return steps if steps else _generic(url_clean, host_clean)


# ── Dispatcher ────────────────────────────────────────────────────────────────

def _dispatch(module, tags, url, host, title, evidence, cve):
    if module == "nmap":
        return _repro_nmap(title, host, evidence)
    if module == "nuclei":
        return _repro_nuclei(title, url, host, evidence, cve)
    if module in ("cors",):
        return _repro_cors(url, host)
    if module in ("tls_ssl", "tls"):
        return _repro_tls(host)
    if module == "takeover":
        return _repro_takeover(title, host, evidence)
    if module == "fuzzing":
        return _repro_fuzzing(url, host, title)
    if module == "secrets":
        return _repro_secrets(url, title, tags)
    if module == "cloud":
        return _repro_cloud(title, url, tags)
    if module in ("header_check", "tech_detection"):
        return _repro_headers(url, title, tags)
    if module == "waf":
        return _repro_waf(host, title)
    if module == "injection":
        return _repro_injection(url, title, tags, evidence)
    if module == "auth_check":
        return _repro_auth(url, title, evidence, tags)
    if module == "recon":
        return _repro_recon(url, host, title, tags)
    if module == "crawl":
        return _repro_crawl(url)
    return []


# ── Módulo: nmap ──────────────────────────────────────────────────────────────

def _repro_nmap(title, host, evidence):
    # Extraer puerto del título o evidencia
    port_match = re.search(r"\b(\d{1,5})\b", title + " " + evidence)
    port = port_match.group(1) if port_match else "PORT"
    host_t = host or "TARGET"
    return [
        f"# Verificar puerto y servicio",
        f"nmap -sV -sC -p {port} {host_t}",
        f"# Escaneo de vulnerabilidades NSE en el puerto",
        f"nmap --script vuln -p {port} {host_t}",
        f"# Banner grab manual",
        f"nc -nv {host_t} {port}",
    ]


# ── Módulo: nuclei ────────────────────────────────────────────────────────────

def _repro_nuclei(title, url, host, evidence, cve):
    target = url or host or "TARGET"
    steps = []
    # Extraer template ID de la evidencia si existe
    tmpl_match = re.search(r"\[([a-z0-9_-]+)\]", evidence or "")
    tmpl = tmpl_match.group(1) if tmpl_match else None

    if cve:
        steps += [
            f"# Explotar con nuclei usando template CVE",
            f"nuclei -u {target} -t cves/{cve.lower()}.yaml",
            f"# Buscar PoC público",
            f"# https://www.google.com/search?q={cve}+PoC+exploit",
        ]
    elif tmpl:
        steps += [
            f"# Re-ejecutar template específico",
            f"nuclei -u {target} -t {tmpl}.yaml -debug",
        ]
    else:
        steps += [
            f"# Re-ejecutar nuclei en el target",
            f"nuclei -u {target} -severity critical,high,medium",
        ]

    steps += [
        f"# Verificar manualmente con curl",
        f"curl -sk {target} -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n'",
    ]
    return steps


# ── Módulo: cors ──────────────────────────────────────────────────────────────

def _repro_cors(url, host):
    target = url or f"https://{host}"
    return [
        f"# Probar reflexión de origen arbitrario",
        f"curl -sk -I -H 'Origin: https://evil.com' '{target}'",
        f"# Verificar header Access-Control-Allow-Origin en respuesta",
        f"curl -sk -I -H 'Origin: null' '{target}'",
        f"# Con credenciales",
        f"curl -sk -I -H 'Origin: https://evil.com' '{target}' | grep -i 'access-control'",
    ]


# ── Módulo: tls_ssl ───────────────────────────────────────────────────────────

def _repro_tls(host):
    host_t = host or "TARGET"
    return [
        f"# Análisis completo TLS/SSL",
        f"sslscan {host_t}:443",
        f"# O con testssl.sh (más detallado)",
        f"testssl.sh --color 0 {host_t}",
        f"# Enumerar cipher suites con nmap",
        f"nmap --script ssl-enum-ciphers -p 443 {host_t}",
        f"# Verificar Heartbleed",
        f"nmap --script ssl-heartbleed -p 443 {host_t}",
    ]


# ── Módulo: takeover ──────────────────────────────────────────────────────────

def _repro_takeover(title, host, evidence):
    sub_match = re.search(r"Takeover[:\s]+([^\s]+)", title, re.IGNORECASE)
    subdomain = sub_match.group(1) if sub_match else (host or "SUBDOMAIN")
    cname_match = re.search(r"CNAME.*?→\s*([^\s\n]+)", evidence or "")
    cname = cname_match.group(1) if cname_match else ""
    steps = [
        f"# Verificar CNAME chain",
        f"dig CNAME {subdomain}",
        f"# Confirmar NXDOMAIN del destino",
    ]
    if cname:
        steps += [f"host {cname}"]
    steps += [
        f"# Comprobar si responde HTTP",
        f"curl -sk https://{subdomain} -I",
        f"# Referencia: https://github.com/EdOverflow/can-i-take-over-xyz",
    ]
    return steps


# ── Módulo: fuzzing ───────────────────────────────────────────────────────────

def _repro_fuzzing(url, host, title):
    base = re.sub(r"/[^/]*$", "", url) if url else f"https://{host}"
    path = re.sub(r"https?://[^/]+", "", url) if url else "/PATH"
    return [
        f"# Verificar recurso directamente",
        f"curl -sk -o /dev/null -w '%{{http_code}} %{{size_download}}b\\n' '{url or base + path}'",
        f"# Fuzzing de directorios con ffuf",
        f"ffuf -u {base}/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404,403 -mc 200,201,301,302",
        f"# Con gobuster",
        f"gobuster dir -u {base} -w /usr/share/wordlists/dirb/common.txt -b 404,403",
    ]


# ── Módulo: secrets ───────────────────────────────────────────────────────────

def _repro_secrets(url, title, tags):
    target = url or "URL_DEL_ARCHIVO_JS"
    secret_type = next((t for t in tags if t not in ("secret", "exposure", "js")), "api_key")
    return [
        f"# Descargar el archivo JS y buscar el secret",
        f"curl -sk '{target}' | grep -Ei '({secret_type}|api[_-]?key|token|secret|password)' | head -20",
        f"# Búsqueda más amplia con gf",
        f"curl -sk '{target}' | gf secrets",
        f"# Validar si el secret sigue activo buscando en documentación de la API",
    ]


# ── Módulo: cloud ─────────────────────────────────────────────────────────────

def _repro_cloud(title, url, tags):
    bucket_match = re.search(r":\s*([a-z0-9._-]+)", title)
    bucket = bucket_match.group(1) if bucket_match else "BUCKET_NAME"

    if "aws-s3" in tags or "s3" in tags:
        return [
            f"# Listar contenido del bucket S3 sin autenticación",
            f"aws s3 ls s3://{bucket} --no-sign-request",
            f"# Verificar ACL pública",
            f"curl -sk 'https://{bucket}.s3.amazonaws.com' | head -50",
            f"# Intentar subir archivo (solo si tienes autorización)",
            f"aws s3 cp test.txt s3://{bucket}/test.txt --no-sign-request",
        ]
    if "gcp" in tags or "gcs" in tags:
        return [
            f"# Listar bucket GCS sin autenticación",
            f"gsutil ls gs://{bucket}",
            f"curl -sk 'https://storage.googleapis.com/{bucket}' | head -50",
        ]
    if "azure" in tags:
        return [
            f"# Enumerar Azure Blob Storage",
            f"curl -sk '{url or f'https://{bucket}.blob.core.windows.net'}' | head -50",
            f"az storage blob list --account-name {bucket} --container-name '$web' --no-auth",
        ]
    return [
        f"# Verificar acceso al recurso cloud",
        f"curl -sk '{url}' -o /dev/null -w '%{{http_code}}\\n'",
        f"curl -sk '{url}' | head -100",
    ]


# ── Módulo: header_check / tech_detection ────────────────────────────────────

def _repro_headers(url, title, tags):
    target = url or "https://TARGET"
    header_map = {
        "hsts":                  "Strict-Transport-Security",
        "csp":                   "Content-Security-Policy",
        "x-frame-options":       "X-Frame-Options",
        "x-content-type":        "X-Content-Type-Options",
        "referrer-policy":       "Referrer-Policy",
        "permissions-policy":    "Permissions-Policy",
        "x-xss-protection":      "X-XSS-Protection",
        "cache-control":         "Cache-Control",
    }
    specific = next((v for k, v in header_map.items() if k in " ".join(tags).lower() or k in title.lower()), None)

    steps = [
        f"# Ver todos los headers de respuesta",
        f"curl -sk -I '{target}'",
    ]
    if specific:
        steps += [
            f"# Verificar header específico: {specific}",
            f"curl -sk -I '{target}' | grep -i '{specific.lower()}'",
        ]
    if "cookie" in title.lower() or "cookie" in " ".join(tags):
        steps += [
            f"# Verificar flags de cookies",
            f"curl -sk -I '{target}' | grep -i 'set-cookie'",
        ]
    steps += [
        f"# Análisis completo de headers con securityheaders.com",
        f"# https://securityheaders.com/?q={urllib.parse.quote(target)}",
    ]
    return steps


# ── Módulo: waf ───────────────────────────────────────────────────────────────

def _repro_waf(host, title):
    target = f"https://{host}" if host else "https://TARGET"
    return [
        f"# Detectar WAF con wafw00f",
        f"wafw00f {target}",
        f"# Identificar fingerprint de respuesta",
        f"curl -sk -I '{target}' | grep -Ei 'server|x-powered|via|x-cache|cf-ray|x-amz'",
        f"# Probar bypass de WAF (requiere autorización explícita)",
        f"curl -sk '{target}/?id=1+AND+1=1' -I",
    ]


# ── Módulo: injection ─────────────────────────────────────────────────────────

def _repro_injection(url, title, tags, evidence):
    target = url or "https://TARGET?param=value"
    steps = []

    if "sql-injection" in tags or "sqli" in title.lower():
        # Intentar extraer param del URL
        param_match = re.search(r"param[:\s]+([a-z_]+)", title + " " + evidence, re.IGNORECASE)
        param = param_match.group(1) if param_match else "id"
        steps = [
            f"# Verificar SQLi error-based",
            f"curl -sk \"{target.split('?')[0]}?{param}='\"",
            f"# Automatizar con sqlmap (requiere autorización)",
            f"sqlmap -u \"{target}\" -p {param} --dbs --batch",
            f"# Confirmar con payload básico",
            f"curl -sk \"{target.split('?')[0]}?{param}=1+AND+1=1\" | grep -i 'error\\|sql\\|syntax'",
        ]
    elif "xss" in tags or "xss" in title.lower():
        steps = [
            f"# Verificar XSS reflejado",
            f"curl -sk \"{target}\" | grep -i '<script\\|onerror\\|onload'",
            f"# Payload manual en navegador",
            f"# Abrir: {target.replace('OrionXSSprobe9f3a', '<script>alert(1)</script>')}",
            f"# Herramienta: dalfox url \"{target}\"",
        ]
    elif "lfi" in tags or "lfi" in title.lower():
        steps = [
            f"# Verificar LFI con payload básico",
            f"curl -sk \"{target}\"",
            f"# Payloads adicionales",
            f"curl -sk \"{target.replace('../../../../etc/passwd', '....//....//....//etc/passwd')}\"",
            f"curl -sk \"{target.replace('../../../../etc/passwd', '%2F%2Fetc%2Fpasswd')}\"",
        ]
    elif "ssrf" in tags or "ssrf" in title.lower():
        steps = [
            f"# Probar SSRF activo con Burp Collaborator o interactsh",
            f"# Reemplazar valor del parámetro con tu URL de callback:",
            f"curl -sk \"{target}\" --data 'url=http://YOUR_INTERACTSH_HOST'",
            f"# Herramienta: interactsh-client (https://github.com/projectdiscovery/interactsh)",
            f"interactsh-client &",
            f"curl -sk '{target.split('?')[0]}?url=http://YOUR_INTERACTSH_HOST'",
        ]
    else:
        steps = [
            f"curl -sk \"{target}\"",
            f"# Revisar respuesta para indicadores de inyección",
        ]
    return steps


# ── Módulo: auth_check ────────────────────────────────────────────────────────

def _repro_auth(url, title, evidence, tags):
    target = url or "https://TARGET"
    steps = []

    if "jwt" in tags or "jwt" in title.lower():
        if "alg:none" in title.lower() or "alg:none" in evidence.lower():
            steps = [
                f"# Verificar JWT alg:none — modificar header y eliminar firma",
                f"# 1. Decodificar JWT: jwt_tool <TOKEN> -t",
                f"# 2. Crear token sin firma: jwt_tool <TOKEN> -X a",
                f"# 3. Enviar token modificado al endpoint:",
                f"curl -sk -H 'Authorization: Bearer <NONE_TOKEN>' '{target}'",
            ]
        elif "weak" in title.lower() or "secret" in title.lower():
            steps = [
                f"# Verificar secret débil con hashcat",
                f"hashcat -a 0 -m 16500 <JWT_TOKEN> /usr/share/wordlists/rockyou.txt",
                f"# O con jwt_tool",
                f"jwt_tool <TOKEN> -C -d /usr/share/wordlists/rockyou.txt",
            ]
        else:
            steps = [
                f"# Analizar JWT",
                f"jwt_tool <TOKEN> -t",
                f"# Decodificar manualmente",
                f"echo '<JWT_PAYLOAD_PART>' | base64 -d 2>/dev/null",
            ]
    elif "default" in title.lower() or "creds" in " ".join(tags):
        cred_match = re.search(r"([a-z]+):([a-z0-9@!#$]+)", evidence or "", re.IGNORECASE)
        user, pwd = (cred_match.group(1), cred_match.group(2)) if cred_match else ("admin", "admin")
        steps = [
            f"# Verificar credenciales por defecto",
            f"curl -sk -u '{user}:{pwd}' '{target}' -o /dev/null -w '%{{http_code}}\\n'",
            f"# O login por formulario",
            f"curl -sk -X POST '{target}' -d 'username={user}&password={pwd}' -L -c /tmp/cookies.txt",
            f"# Ver respuesta con cookies",
            f"curl -sk '{target}' -b /tmp/cookies.txt | grep -i 'dashboard\\|logout\\|welcome'",
        ]
    else:
        steps = [
            f"curl -sk '{target}' -I",
            f"# Revisar autenticación requerida (401/403) y mecanismo",
        ]
    return steps


# ── Módulo: recon ─────────────────────────────────────────────────────────────

def _repro_recon(url, host, title, tags):
    target = url or f"https://{host}"
    host_t = host or "TARGET_DOMAIN"

    if "historical-url" in tags or "gau" in tags:
        return [
            f"# Verificar si la URL sigue activa",
            f"curl -sk -o /dev/null -w '%{{http_code}}\\n' '{target}'",
            f"# Ver snapshot en Wayback Machine",
            f"curl -sk 'https://archive.org/wayback/available?url={urllib.parse.quote(target)}' | python3 -m json.tool",
        ]
    if "subdomain" in tags or "crtsh" in tags:
        domain = host_t
        return [
            f"# Enumerar subdominios",
            f"subfinder -d {domain} -silent",
            f"amass enum -passive -d {domain}",
            f"# Verificar cuáles están vivos",
            f"subfinder -d {domain} -silent | httpx -silent -status-code",
        ]
    if "email" in tags:
        return [
            f"# Verificar emails con theHarvester",
            f"theHarvester -d {host_t} -b google,bing",
            f"# Verificar si el email tiene brechas conocidas",
            f"# https://haveibeenpwned.com",
        ]
    return [
        f"# Verificar recurso",
        f"curl -sk '{target}' -o /dev/null -w '%{{http_code}}\\n'",
        f"httpx -u '{target}' -status-code -title -tech-detect",
    ]


# ── Módulo: crawl ─────────────────────────────────────────────────────────────

def _repro_crawl(url):
    target = url or "https://TARGET"
    return [
        f"# Verificar endpoint directamente",
        f"curl -sk '{target}' -o /dev/null -w '%{{http_code}} %{{content_type}}\\n'",
        f"curl -sk '{target}' | head -200",
        f"# Crawl adicional con katana",
        f"katana -u '{target}' -depth 2 -silent",
    ]


# ── Genérico ──────────────────────────────────────────────────────────────────

def _generic(url, host):
    target = url or (f"https://{host}" if host else "TARGET")
    return [
        f"# Verificar manualmente",
        f"curl -sk '{target}' -I",
        f"curl -sk '{target}' | head -100",
    ]
