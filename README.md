# ⭐ OrionRecon — Attack Surface Recon Toolkit

> **By Jorge RC**

Framework modular de reconocimiento y pentesting con pipeline automatizado, escaneo de vulnerabilidades y dashboard HTML interactivo estilo HackerOne.

> ⚠️ **Solo para uso en sistemas con autorización explícita. El uso no autorizado puede ser ilegal.**

---

## Módulos

| Módulo | Herramientas | Descripción |
|--------|-------------|-------------|
| 🌐 **Recon / OSINT** | theHarvester, amass, subfinder, crt.sh | Enumeración pasiva de subdominios, emails, IPs |
| 🔫 **Nmap Artillery** | nmap | 10 perfiles: quick, stealth, full, vuln, udp, web, smb... |
| 💊 **Nuclei** | nuclei | Detección de vulnerabilidades con templates |
| 🔬 **Tech Detection** | requests | Fingerprinting de tecnologías (Wappalyzer-like) |
| 🎯 **Takeover Check** | dns, requests | Detección de subdomain takeover (20+ servicios) |
| 💥 **Fuzzing** | ffuf | Directory, parameter y vhost fuzzing |
| 📊 **Dashboard** | — | Reporte HTML dark theme, filtros, timeline, export JSON |

---

## Instalación

```bash
git clone https://github.com/JorgRCz/orionrecon.git
cd orionrecon
bash install.sh
```

El script instala automáticamente:
- Dependencias Python
- theHarvester, subfinder, nuclei, ffuf, amass (si tienes Go)
- SecLists (wordlists)
- Comando global `orionrecon`

### Requisitos

- Python 3.10+
- Go 1.21+ *(para subfinder, nuclei, ffuf, amass)*
- nmap
- Kali Linux / Parrot OS / Ubuntu recomendado

---

## Uso rápido

```bash
# Verificar herramientas instaladas
orionrecon check

# Scan completo
orionrecon scan objetivo.com

# Módulos específicos
orionrecon scan objetivo.com -m recon nmap nuclei tech takeover fuzzing

# Solo recon OSINT
orionrecon recon objetivo.com

# Nmap con múltiples perfiles
orionrecon nmap 192.168.1.1 -p quick web vuln

# Tech detection
orionrecon tech https://objetivo.com

# Fuzzing
orionrecon fuzz https://objetivo.com -m directories parameters vhosts --domain objetivo.com

# Regenerar reporte HTML de sesión existente
orionrecon report ./sessions/objetivo.com_20240101_120000/
```

---

## Perfiles Nmap

| Perfil | Flags | Descripción |
|--------|-------|-------------|
| `quick` | `-T4 -F --open` | 100 puertos más comunes |
| `stealth` | `-sS -T2 -p- --open -Pn` | SYN scan silencioso |
| `full` | `-sS -sV -sC -O -T4 -p-` | Todos los puertos + versiones + scripts |
| `vuln` | `-sV --script=vuln -T4` | Scripts NSE de vulnerabilidades |
| `udp` | `-sU -T4 --top-ports 200` | UDP top 200 puertos |
| `aggressive` | `-A -T4 -p-` | OS, versión, traceroute |
| `web` | `-sV -p 80,443,8080,8443...` | Solo puertos web |
| `smb` | `-p 139,445 --script=smb-vuln*` | Vulnerabilidades SMB |

---

## Dashboard

Cada scan genera un reporte HTML interactivo en `sessions/<target>_<timestamp>/report.html`:

- **Overview** — stats por severidad, módulos ejecutados, top findings
- **Findings** — tabla completa con filtros y búsqueda, filas expandibles con evidencia
- **Recon** — subdominios, hosts vivos, emails
- **Nmap** — puertos y servicios por perfil
- **Tech Detection** — tecnologías detectadas, headers de seguridad faltantes
- **Takeover** — subdominios vulnerables con cadena CNAME
- **Fuzzing** — paths, parámetros y vhosts descubiertos
- **Timeline** — línea de tiempo del scan con findings críticos
- **Export JSON** — exportar todos los datos

---

## Estructura del proyecto

```
orionrecon/
├── pentest.py              # CLI principal
├── config.yaml             # Configuración
├── install.sh              # Instalador automático
├── requirements.txt
└── modules/
    ├── core/               # Motor paralelo, storage, logger
    ├── recon/              # theHarvester, amass, subfinder, crt.sh
    ├── scanning/           # Nmap, Nuclei
    ├── tech/               # Fingerprinting de tecnologías
    ├── takeover/           # Subdomain takeover detection
    ├── fuzzing/            # ffuf wrapper
    └── reporting/          # Dashboard HTML
```

---

## Configuración

Edita `config.yaml` para personalizar:

```yaml
api_keys:
  shodan: "TU_API_KEY"
  virustotal: "TU_API_KEY"

nuclei:
  severity: ["critical", "high", "medium"]

nmap:
  profiles:
    custom:
      flags: "-sV -p 8080,8443 --open"
      description: "Puertos personalizados"
```

---

## Disclaimer

Esta herramienta es únicamente para:
- Pruebas en sistemas propios
- Engagements de pentesting con autorización escrita
- Entornos de laboratorio / CTFs
- Investigación de seguridad defensiva

El autor no se hace responsable del uso indebido.

---

**OrionRecon** · By Jorge RC
