"""
Cloud Infrastructure Scanner.
Detecta activos cloud expuestos: AWS S3, GCP GCS, Azure Blob, DigitalOcean Spaces.
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("cloud.scanner")

TIMEOUT = 6

# CNAMEs que indican presencia en servicios cloud
CLOUD_CNAME_PATTERNS = {
    "AWS S3":         [".s3.amazonaws.com", ".s3-website"],
    "AWS CloudFront": [".cloudfront.net"],
    "AWS ELB":        [".elb.amazonaws.com", ".compute.amazonaws.com"],
    "GCP Storage":    [".storage.googleapis.com"],
    "GCP App Engine": [".appspot.com"],
    "GCP Run":        [".run.app"],
    "Azure":          [".azurewebsites.net", ".blob.core.windows.net",
                       ".cloudapp.azure.com", ".azureedge.net", ".trafficmanager.net"],
    "DigitalOcean":   [".digitaloceanspaces.com"],
    "Heroku":         [".herokudns.com", ".herokuapp.com"],
    "Fastly":         [".fastly.net", ".fastlylb.net"],
    "Render":         [".onrender.com"],
    "Vercel":         [".vercel.app"],
    "Netlify":        [".netlify.app"],
}

BUCKET_SUFFIXES = [
    "", "-backup", "-dev", "-prod", "-test", "-staging",
    "-www", "-data", "-assets", "-static", "-files", "-images",
    "-uploads", "-media", "-public", "-private", "-api",
    "-logs", "-config", "-internal",
]


def _get_bucket_names(domain: str) -> list[str]:
    """Genera variaciones de nombre de bucket basadas en el dominio."""
    base = domain.split(".")[0]
    clean_domain = domain.replace(".", "-")
    names = set()
    for base_name in [base, clean_domain]:
        for suffix in BUCKET_SUFFIXES:
            names.add(f"{base_name}{suffix}")
    return list(names)


def _check_s3(bucket_name: str) -> dict | None:
    """Verifica si un bucket S3 es accesible públicamente."""
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]
    for url in urls:
        try:
            r = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200, 403):
                return {
                    "service": "AWS S3",
                    "bucket": bucket_name,
                    "url": url,
                    "status": r.status_code,
                    "public": r.status_code == 200,
                    "severity": "high" if r.status_code == 200 else "medium",
                }
        except Exception as e:
            log.debug(f"S3 check failed for {bucket_name}: {e}")
    return None


def _check_gcs(bucket_name: str) -> dict | None:
    """Verifica si un bucket GCS es público."""
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        r = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code in (200, 403):
            return {
                "service": "GCP GCS",
                "bucket": bucket_name,
                "url": url,
                "status": r.status_code,
                "public": r.status_code == 200,
                "severity": "high" if r.status_code == 200 else "medium",
            }
    except Exception as e:
        log.debug(f"GCS check failed for {bucket_name}: {e}")
    return None


def _check_azure(name: str) -> dict | None:
    """Verifica si una cuenta Azure Blob Storage existe."""
    url = f"https://{name}.blob.core.windows.net"
    try:
        r = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
        # 400 = cuenta existe pero solicitud inválida; 403 = protegido; 200 = público
        if r.status_code in (200, 400, 403):
            return {
                "service": "Azure Blob",
                "bucket": name,
                "url": url,
                "status": r.status_code,
                "public": r.status_code == 200,
                "severity": "high" if r.status_code == 200 else "medium",
            }
    except Exception as e:
        log.debug(f"Azure check failed for {name}: {e}")
    return None


def _check_do_spaces(name: str) -> dict | None:
    """Verifica DigitalOcean Spaces en las regiones más comunes."""
    for region in ["nyc3", "ams3", "sgp1", "fra1", "sfo3"]:
        url = f"https://{name}.{region}.digitaloceanspaces.com"
        try:
            r = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200, 403):
                return {
                    "service": "DigitalOcean Spaces",
                    "bucket": name,
                    "url": url,
                    "status": r.status_code,
                    "public": r.status_code == 200,
                    "severity": "high" if r.status_code == 200 else "medium",
                }
        except Exception as e:
            log.debug(f"DO Spaces check failed for {name} ({region}): {e}")
    return None


def _detect_cloud_cnames(recon_results: dict) -> list[dict]:
    """Detecta servicios cloud en los CNAMEs obtenidos del recon."""
    detections = []
    if not recon_results:
        return detections

    for host_info in recon_results.get("resolved", []):
        for cname in host_info.get("cnames", []):
            for service, patterns in CLOUD_CNAME_PATTERNS.items():
                if any(p.lower() in cname.lower() for p in patterns):
                    detections.append({
                        "host": host_info["host"],
                        "cname": cname,
                        "service": service,
                        "ips": host_info.get("ips", []),
                    })
                    break
    return detections


class CloudScanner:
    MODULE_NAME = "cloud"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage
        self.max_threads = config.get("general", {}).get("max_threads", 10)

    def run(self, target: str, recon_results: dict | None = None) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
        console.rule(f"[module] CLOUD SCAN → {domain} [/]")

        results = {
            "domain": domain,
            "buckets": [],
            "cname_detections": [],
        }

        # Fase 1: detectar cloud services en CNAMEs del recon
        if recon_results:
            console.print("[info]Fase 1:[/] Detectando servicios cloud en CNAMEs...")
            cname_detections = _detect_cloud_cnames(recon_results)
            results["cname_detections"] = cname_detections
            console.print(f"  → [bold]{len(cname_detections)}[/] detecciones CNAME")
        else:
            console.print("[info]Fase 1:[/] Sin datos de recon previo, omitiendo detección CNAME")

        # Fase 2: enumerar buckets
        console.print(f"[info]Fase 2:[/] Enumerando buckets cloud para [bold]{domain}[/]...")
        bucket_names = _get_bucket_names(domain)
        found_buckets = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = []
            for name in bucket_names:
                futures.append(ex.submit(_check_s3, name))
                futures.append(ex.submit(_check_gcs, name))
                futures.append(ex.submit(_check_azure, name))
                futures.append(ex.submit(_check_do_spaces, name))

            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    found_buckets.append(res)

        results["buckets"] = found_buckets

        # Crear findings
        for b in found_buckets:
            public = b.get("public", False)
            name = b.get("bucket", "")
            self.storage.add_finding(
                title=f"{'Bucket público' if public else 'Bucket expuesto'}: {name} ({b['service']})",
                severity=b.get("severity", "medium"),
                module=self.MODULE_NAME,
                description=(
                    f"{'Acceso público con listado de contenido posible' if public else 'Bucket encontrado con acceso restringido'} "
                    f"en {b['service']}. Status HTTP: {b['status']}."
                ),
                host=domain,
                url=b["url"],
                evidence=f"URL: {b['url']} | HTTP {b['status']} | Público: {public}",
                tags=["cloud", b["service"].lower().replace(" ", "-"), "bucket"],
            )

        for det in results["cname_detections"]:
            self.storage.add_finding(
                title=f"Servicio cloud detectado via DNS: {det['host']} → {det['service']}",
                severity="info",
                module=self.MODULE_NAME,
                description=f"CNAME apunta a {det['service']}: {det['cname']}",
                host=det["host"],
                evidence=f"CNAME: {det['cname']} | IPs: {', '.join(det.get('ips', []))}",
                tags=["cloud", "cname", det["service"].lower().replace(" ", "-")],
            )

        self.storage.save_module(self.MODULE_NAME, results)

        console.print(f"\n[success]✓ Cloud scan completo:[/]")
        console.print(f"  Buckets encontrados  : [bold]{len(found_buckets)}[/]")
        console.print(f"  Detecciones CNAME    : [bold]{len(results['cname_detections'])}[/]")

        return results
