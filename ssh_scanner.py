#!/usr/bin/env python3
"""
ssh_scanner.py — Scanner Proativo de Servidores SSH com OpenSSH Possivelmente Vulnerável
------------------------------------------------------------------------------------------
Varre os alvos (IPs, CIDRs, ASNs) em busca de instâncias OpenSSH expostas e classifica
sua versão em relação às CVEs conhecidas, identificando versões vulneráveis conhecidas:
CVE-2024-6387 (regreSSHion) — OpenSSH < 9.8p1
CVE-2023-48795 (Terrapin) — OpenSSH < 9.6
Saída estruturada com IP, porta, timestamp, domínio e detalhes:
IP | Porta | Timestamp (UTC) | Dominio | Detalhes
Aceita IPs individuais, faixas CIDR e ASNs como entrada.
Exemplos de uso:
python ssh_scanner.py --ip 192.168.1.10
python ssh_scanner.py --cidr 192.168.0.0/24
python ssh_scanner.py --asn AS12345
python ssh_scanner.py --file alvos.txt
Dependências:
pip install packaging dnspython
"""
import re
import os
import sys
import csv
import time
import json
import socket
import argparse
import ipaddress
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import threading
from datetime import datetime, timezone
from functools import lru_cache
from packaging import version
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
# --- ANSI Colors -------------------------------------------------------------
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
RESET = '\033[0m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
GREY = '\033[90m'
GREEN_DARK = '\033[0;32m'
# --- Configuração CVEs -------------------------------------------------------
# CVE-2024-6387 (regreSSHion): afeta OpenSSH < 9.8p1
# CVE-2023-48795 (Terrapin): afeta OpenSSH < 9.6
CVES = {
    "CVE-2024-6387": {
        "name": "regreSSHion",
        "fixed": "9.8p1",
        "desc": "RCE não autenticado via race condition no handler de sinal",
        "severity": "CRITICAL",
    },
    "CVE-2023-48795": {
        "name": "Terrapin",
        "fixed": "9.6",
        "desc": "Prefix truncation attack no protocolo SSH (BEP)",
        "severity": "HIGH",
    },
}
# Porta SSH padrão e alternativas comuns
SSH_PORTS = [22]
SSH_TIMEOUT = 3.0
DNS_WORKERS = 200
DNS_TIMEOUT = 1.5
# --- Caminhos de saída -------------------------------------------------------
LOG_DIR = "./logs"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"{LOG_DIR}/ssh_scan_{TIMESTAMP}.log"
LOG_VULN = f"{LOG_DIR}/ssh_scan_{TIMESTAMP}_vulneraveis.txt"
LOG_CSV = f"{LOG_DIR}/ssh_scan_{TIMESTAMP}_resultados.csv"
LOG_CERT = f"{LOG_DIR}/ssh_scan_{TIMESTAMP}_formato_estruturado.csv"
_log_lock = threading.Lock()
# =============================================================================
# Log
# =============================================================================
def log(level: str, msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {
        "VULN": f"{RED}[VULN]{RESET}",
        "WARN": f"{YELLOW}[AVISO]{RESET}",
        "OK": f"{GREEN}[SEGURO]{RESET}",
        "INFO": f"{CYAN}[INFO]{RESET}",
        "ERR": f"{RED}[ERRO]{RESET}",
        "HEAD": "",
        "STRUCT": f"{MAGENTA}[STRUCT]{RESET}",
    }
    if level == "HEAD":
        line = f"{BOLD}{CYAN}{msg}{RESET}"
    else:
        line = f"{ts} {colors.get(level, '')} {msg}"
    print(line)
    clean = re.sub(r'\033\[[0-9;]*m', '', line)
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(clean + "\n")
# =============================================================================
# DNS — resolução reversa em batch paralelo
# =============================================================================
def _resolve_ptr_dnspython(ip: str) -> str:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        rev = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev, "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        return "SEM-PTR"
def _resolve_ptr_socket(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "SEM-PTR"
@lru_cache(maxsize=65536)
def get_hostname(ip: str) -> str:
    if HAS_DNSPYTHON:
        return _resolve_ptr_dnspython(ip)
    return _resolve_ptr_socket(ip)
def resolve_hostnames_batch(ips: list) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        futures = {executor.submit(get_hostname, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            results[ip] = future.result()
    return results
# =============================================================================
# Resolução de alvos (ASN / CIDR / IP)
# =============================================================================
def resolve_asn_ripe(asn_number: str) -> list:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "ssh-scanner/1.0"}, verify=False)
        resp.raise_for_status()
        data = resp.json()
        prefixes = [
            p["prefix"] for p in data.get("data", {}).get("prefixes", [])
            if ":" not in p.get("prefix", ":")
        ]
        log("INFO", f"AS{asn_number} — {len(prefixes)} prefixo(s) originado(s) encontrado(s) via RIPE")
        return prefixes
    except Exception as e:
        log("ERR", f"RIPE Stat falhou para AS{asn_number}: {e}")
        return []
def resolve_asn(asn: str) -> list:
    asn_number = asn.upper().lstrip("AS")
    log("INFO", f"Resolvendo {asn.upper()} via RIPE Stat ...")
    prefixes = resolve_asn_ripe(asn_number)
    if prefixes:
        return prefixes
    log("WARN", f"RIPE Stat não retornou prefixos para {asn.upper()}. Tentando bgp.tools ...")
    url = f"https://bgp.tools/table.jsonl?asn={asn_number}"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "ssh-scanner/1.0"}, verify=False)
        resp.raise_for_status()
        prefixes = []
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                prefix = entry.get("CIDR") or entry.get("prefix") or entry.get("cidr")
                origin = str(entry.get("ASN") or entry.get("origin_asn") or entry.get("origin") or "")
                if prefix and ":" not in prefix and origin == asn_number:
                    prefixes.append(prefix)
            except Exception:
                try:
                    ipaddress.ip_network(line, strict=False)
                    if ":" not in line:
                        prefixes.append(line)
                except ValueError:
                    pass
        log("INFO", f"{asn.upper()} — {len(prefixes)} prefixo(s) IPv4 encontrado(s) via bgp.tools")
        return prefixes
    except Exception as e:
        log("ERR", f"bgp.tools também falhou para {asn.upper()}: {e}")
        return []
def expand_targets(ips=None, cidrs=None, asns=None, file=None) -> list:
    all_prefixes = []
    if ips:
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                all_prefixes.append(f"{ip}/32")
            except ValueError:
                if "/" in ip:
                    log("WARN", f"'{ip}' parece um CIDR — use --cidr em vez de --ip")
                else:
                    log("WARN", f"Endereço IP inválido ignorado: '{ip}'")
    if cidrs:
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
                all_prefixes.append(cidr)
            except ValueError:
                log("WARN", f"CIDR inválido ignorado: '{cidr}'")
    if asns:
        for asn in asns:
            all_prefixes.extend(resolve_asn(asn))
    if file:
        try:
            with open(file, encoding="utf-8") as fh:
                for raw in fh:
                    entry = raw.strip()
                    if not entry or entry.startswith("#"):
                        continue
                    upper = entry.upper()
                    if upper.startswith("AS") or upper.isdigit():
                        all_prefixes.extend(resolve_asn(entry))
                    elif "/" in entry:
                        try:
                            ipaddress.ip_network(entry, strict=False)
                            all_prefixes.append(entry)
                        except ValueError:
                            log("WARN", f"CIDR inválido no arquivo ignorado: {entry}")
                    else:
                        try:
                            ipaddress.ip_address(entry)
                            all_prefixes.append(f"{entry}/32")
                        except ValueError:
                            log("WARN", f"Entrada inválida no arquivo ignorada: {entry}")
        except FileNotFoundError:
            log("ERR", f"Arquivo não encontrado: {file}")
            sys.exit(1)
    seen = set()
    unique = []
    for p in all_prefixes:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique
# =============================================================================
# Banner SSH — leitura do banner de identificação
# =============================================================================
def grab_ssh_banner(ip: str, port: int = 22, timeout: float = SSH_TIMEOUT) -> str | None:
    """
    Conecta na porta SSH e lê o banner de identificação (ex: SSH-2.0-OpenSSH_9.7).
    Retorna a string do banner ou None se falhar / não for SSH.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        sock.close()
        if banner.startswith("SSH-"):
            return banner
        return None
    except Exception:
        return None
# =============================================================================
# Análise de versão e CVEs
# =============================================================================
def parse_openssh_version(banner: str) -> str | None:
    """
    Extrai a versão OpenSSH do banner.
    Ex: 'SSH-2.0-OpenSSH_9.7' → '9.7'
    'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719' → '9.3'
    """
    match = re.search(r"OpenSSH[_\s]([\d.p]+)", banner, re.IGNORECASE)
    if match:
        return match.group(1)
    return None
def detect_ssh_software(banner: str) -> tuple:
    """
    Identifica o fabricante/software SSH e extrai nome + versão do servidor.
    Retorna (fabricante, server_name, server_version).
    Ex: 'SSH-2.0-OpenSSH_9.7' → ('OpenSSH', 'OpenSSH', '9.7')
    'SSH-2.0-ROSSSH' → ('Mikrotik', 'ROSSSH', 'N/D')
    'SSH-2.0-Cisco-1.25' → ('Cisco', 'Cisco', '1.25')
    'SSH-2.0-dropbear_2022.83' → ('Dropbear', 'dropbear', '2022.83')
    'SSH-2.0-OpenSSH_9.3 FreeBSD-...' → ('OpenSSH', 'OpenSSH', '9.3')
    """
    match_sw = re.match(r"SSH-[\d.]+-(.+)", banner)
    raw = match_sw.group(1).strip() if match_sw else banner
    match_ver = re.match(r"([A-Za-z][A-Za-z0-9\-\.]+)[_\-]([\d][\d\.p\-a-zA-Z]*)", raw)
    if match_ver:
        sw_name = match_ver.group(1)
        sw_ver = match_ver.group(2)
    else:
        sw_name = raw.split()[0]
        sw_ver = "N/D"
    fabricante_map = {
        "openssh": "OpenSSH",
        "rosssh": "Mikrotik",
        "cisco": "Cisco",
        "dropbear": "Dropbear",
        "libssh": "libssh",
        "bitvise": "Bitvise",
        "paramiko": "Paramiko",
        "asyncssh": "AsyncSSH",
        "huawei": "Huawei",
        "junos": "Juniper",
        "vshell": "VShell",
        "wolfsssh": "wolfSSH",
        "cryptlib": "cryptlib",
    }
    fabricante = fabricante_map.get(sw_name.lower(), sw_name)
    return fabricante, sw_name, sw_ver
def _normalize_ver(ver_str: str) -> str:
    """Normaliza versão OpenSSH para comparação (ex: 9.8p1 → 9.8.1, 9.6 → 9.6.0)."""
    ver_str = ver_str.strip()
    ver_str = re.sub(r'p(\d+)', r'.\1', ver_str)
    return ver_str
def is_ubuntu_patched(banner: str, cve_id: str) -> bool:
    """
    Detecta backports Ubuntu/Debian pelo sufixo do banner.
    Ex: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15'

    Revisoes conhecidas para Ubuntu 22.04 (OpenSSH 8.9p1):
      ubuntu0.6+  -> CVE-2023-48795 corrigida
      ubuntu0.10+ -> CVE-2024-6387  corrigida

    Revisoes conhecidas para Ubuntu 20.04 (OpenSSH 8.2p1):
      ubuntu0.10+ -> CVE-2023-48795 corrigida
      ubuntu0.12+ -> CVE-2024-6387  corrigida
    """
    openssh_ver = parse_openssh_version(banner)
    if not openssh_ver:
        return False

    # Ubuntu 22.04 e 20.04
    match = re.search(r'Ubuntu-\d+ubuntu0\.(\d+)', banner, re.IGNORECASE)
    if match:
        patch_rev = int(match.group(1))
        if openssh_ver.startswith("8.9"):
            if cve_id == "CVE-2024-6387" and patch_rev >= 10:
                return True
            if cve_id == "CVE-2023-48795" and patch_rev >= 6:
                return True
        if openssh_ver.startswith("8.2"):
            if cve_id == "CVE-2024-6387" and patch_rev >= 12:
                return True
            if cve_id == "CVE-2023-48795" and patch_rev >= 10:
                return True

    # Debian 12 Bookworm (ex: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3)
    # CVE-2023-48795: fixed in deb12u2 | CVE-2024-6387: fixed in deb12u3
    match_deb = re.search(r'Debian-\d+\+deb12u(\d+)', banner, re.IGNORECASE)
    if match_deb:
        deb_rev = int(match_deb.group(1))
        if openssh_ver.startswith("9.2"):
            if cve_id == "CVE-2024-6387" and deb_rev >= 3:
                return True
            if cve_id == "CVE-2023-48795" and deb_rev >= 2:
                return True

    return False

def check_cves(openssh_version: str, banner: str = "") -> list:
    """
    Verifica quais CVEs afetam a versao OpenSSH informada.
    Considera backports Ubuntu/Debian pelo sufixo do banner.
    Retorna lista de CVE IDs afetados.
    """
    affected = []
    try:
        current = version.parse(_normalize_ver(openssh_version))
    except Exception:
        return []
    for cve_id, info in CVES.items():
        try:
            fixed = version.parse(_normalize_ver(info["fixed"]))
            if current < fixed:
                if not is_ubuntu_patched(banner, cve_id):
                    affected.append(cve_id)
        except Exception:
            pass
    return affected
def classify_host(banner: str, openssh_ver: str | None, affected_cves: list) -> str:
    """Retorna status textual do host."""
    if not banner.startswith("SSH-"):
        return "NÃO-SSH"
    if "openssh" not in banner.lower():
        return "SSH-NÃO-OPENSSH"
    if openssh_ver is None:
        return "VERSÃO-OCULTA"
    if affected_cves:
        return "VULNERÁVEL"
    return "SEGURO"
# =============================================================================
# Scanner SSH principal
# =============================================================================
def scan_ip_ssh(ip: str, hostname: str, ports: list, timeout: float) -> dict | None:
    """
    Sonda um IP nas portas SSH informadas.
    Retorna dict com resultado ou None se SSH não encontrado.
    """
    for port in ports:
        banner = grab_ssh_banner(ip, port, timeout)
        if banner is None:
            continue
        openssh_ver = parse_openssh_version(banner)
        fabricante, sw_name, sw_ver = detect_ssh_software(banner)
        affected_cves = check_cves(openssh_ver, banner) if openssh_ver else []
        status = classify_host(banner, openssh_ver, affected_cves)
        return {
            "ip": ip,
            "port": port,
            "hostname": hostname,
            "banner": banner,
            "openssh_ver": openssh_ver or "N/D",
            "fabricante": fabricante,
            "sw_name": sw_name,
            "sw_ver": sw_ver,
            "affected_cves": affected_cves,
            "status": status,
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    return None
# =============================================================================
# Formatação estruturada de saída
# =============================================================================
def format_cert_row(res: dict) -> dict:
    """Gera dict para linha CSV estruturada."""
    cves_str = ";".join(res["affected_cves"]).lower()
    return {
        "IP": res["ip"],
        "PORTA": res["port"],
        "TIMESTAMP_UTC": res["timestamp_utc"],
        "DOMINIO": res["hostname"],
        "FABRICANTE": res["fabricante"],
        "SW_NAME": res["sw_name"],
        "SW_VERSAO": res["sw_ver"],
        "CVEs": cves_str,
        "BANNER": res["banner"],
    }
# =============================================================================
# CLI
# =============================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="SSH OpenSSH — Scanner Proativo de Vulnerabilidades (CVE-2024-6387 / CVE-2023-48795)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --ip 192.168.1.10
  %(prog)s --cidr 192.168.0.0/24
  %(prog)s --asn AS12345
  %(prog)s --asn AS12345 AS67890 --cidr 10.0.0.0/8
  %(prog)s --file alvos.txt
  %(prog)s --cidr 192.168.0.0/24 --workers 100 --timeout 4 --ports 22 2222
""",
    )
    parser.add_argument("--ip",          nargs="+", metavar="IP",      help="Um ou mais IPs individuais")
    parser.add_argument("--cidr",        nargs="+", metavar="CIDR",    help="Uma ou mais faixas CIDR")
    parser.add_argument("--asn",         nargs="+", metavar="ASN",     help="Um ou mais ASNs (ex: AS12345)")
    parser.add_argument("--file",        metavar="ARQUIVO",            help="Arquivo com IPs, CIDRs e/ou ASNs (um por linha)")
    parser.add_argument("--ports",       nargs="+", type=int, default=SSH_PORTS, metavar="PORTA",
                        help=f"Portas SSH a varrer (padrão: {SSH_PORTS})")
    parser.add_argument("--workers",     type=int,   default=60,        help="Threads para scan SSH (padrão: 60)")
    parser.add_argument("--dns-workers", type=int,   default=DNS_WORKERS,
                        help=f"Threads para resolução DNS (padrão: {DNS_WORKERS})")
    parser.add_argument("--timeout",     type=float, default=SSH_TIMEOUT,
                        help=f"Timeout da conexão SSH em segundos (padrão: {SSH_TIMEOUT})")
    parser.add_argument("--dns-timeout", type=float, default=DNS_TIMEOUT,
                        help=f"Timeout das queries DNS em segundos (padrão: {DNS_TIMEOUT})")
    parser.add_argument("--no-confirm",  action="store_true",           help="Pula confirmação antes de iniciar")
    return parser.parse_args()
def normalize_argv():
    normalized = []
    for arg in sys.argv[1:]:
        if arg.startswith("--") and not arg.startswith("--no"):
            normalized.append(arg.lower())
        else:
            normalized.append(arg)
    sys.argv[1:] = normalized
# =============================================================================
# Main
# =============================================================================
def main():
    normalize_argv()
    args = parse_args()
    if not any([args.ip, args.cidr, args.asn, args.file]):
        print(f"\n{YELLOW}[OPA]{RESET} Nenhum alvo especificado.")
        print(f"\n {BOLD}Alvos {GREY}(obrigatório — um ou mais):{RESET}")
        print(f"  {CYAN}--ip{RESET}   <IP ...>      IP(s) individual(is)   ex: --ip 192.168.1.10")
        print(f"  {CYAN}--cidr{RESET} <CIDR ...>    Faixa(s) de rede       ex: --cidr 192.168.0.0/24")
        print(f"  {CYAN}--asn{RESET}  <ASN ...>     Sistema(s) autônomo(s) ex: --asn AS12345")
        print(f"  {CYAN}--file{RESET} <arquivo>     Arquivo de alvos       ex: --file alvos.txt")
        print(f"\n {BOLD}Opções adicionais:{RESET}")
        print(f"  {CYAN}--ports{RESET}       <PORTA ...>  Portas SSH a varrer    ex: --ports 22 2222  {GREY}(padrão: {SSH_PORTS}){RESET}")
        print(f"  {CYAN}--workers{RESET}     <N>          Threads scan SSH       {GREY}(padrão: 60){RESET}")
        print(f"  {CYAN}--dns-workers{RESET} <N>          Threads resolução DNS  {GREY}(padrão: {DNS_WORKERS}){RESET}")
        print(f"  {CYAN}--timeout{RESET}     <seg>        Timeout conexão SSH    {GREY}(padrão: {SSH_TIMEOUT}s){RESET}")
        print(f"  {CYAN}--dns-timeout{RESET} <seg>        Timeout query DNS      {GREY}(padrão: {DNS_TIMEOUT}s){RESET}")
        print(f"  {CYAN}--no-confirm{RESET}               Pula confirmação antes de iniciar")
        print(f"\n  Execute com {BOLD}--help{RESET} para ver todos os parâmetros.\n")
        sys.exit(1)
    os.makedirs(LOG_DIR, exist_ok=True)
    # Banner
    print(f"""{GREEN_DARK}
 ███████╗███████╗██╗  ██╗  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔════╝██╔════╝██║  ██║  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ███████╗███████╗███████║  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ╚════██║╚════██║██╔══██║  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ███████║███████║██║  ██║  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{RESET}""")
    print(f" \033[90m{'─' * 77}\033[0m")
    print(f"  {YELLOW}CVE-2024-6387{RESET}  \033[90m│\033[0m  {CYAN}regreSSHion{RESET}  \033[90m│\033[0m  OpenSSH < 9.8p1 — RCE não autenticado")
    print(f"  {YELLOW}CVE-2023-48795{RESET}  \033[90m│\033[0m  {CYAN}Terrapin{RESET}  \033[90m│\033[0m  OpenSSH < 9.6 — Prefix truncation attack")
    print(f" \033[90m{'─' * 77}\033[0m\n")
    if not HAS_DNSPYTHON:
        print(f" {YELLOW}[AVISO]{RESET} dnspython não instalado — usando socket padrão para DNS (mais lento).")
        print(f" Instale com: {CYAN}pip install dnspython{RESET}\n")
    # Resolve alvos
    prefixes = expand_targets(
        ips=args.ip,
        cidrs=args.cidr,
        asns=args.asn,
        file=args.file,
    )
    if not prefixes:
        print(f"\n{RED}[ERR]{RESET} Nenhum alvo válido encontrado após resolução.\n")
        sys.exit(1)
    total_hosts = sum(
        ipaddress.ip_network(p, strict=False).num_addresses - (2 if ipaddress.ip_network(p, strict=False).prefixlen < 31 else 0)
        for p in prefixes
    )
    print(f" {BOLD}Alvos resolvidos:{RESET} {len(prefixes)} prefixo(s) / ~{total_hosts:,} host(s)")
    print(f" {BOLD}Portas SSH:{RESET} {args.ports}\n")
    for p in prefixes:
        net = ipaddress.ip_network(p, strict=False)
        print(f" {CYAN}•{RESET} {p:<20} ({net.num_addresses} addr)")
    print()
    if not args.no_confirm:
        confirm = input(f" {BOLD}Iniciar varredura? [s/N]:{RESET} ").strip().lower()
        if confirm != "s":
            print(" Cancelado.")
            sys.exit(0)
    # Inicializa arquivos de saída
    with open(LOG_CERT, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=["IP", "PORTA", "TIMESTAMP_UTC", "DOMINIO", "FABRICANTE", "SW_NAME", "SW_VERSAO", "CVEs", "BANNER"]).writeheader()
    with open(LOG_VULN, "w", encoding="utf-8") as f:
        f.write(f"# SSH VULNERÁVEL | {TIMESTAMP}\n")
        f.write(f"{'IP':<16} {'PORTA':<6} {'HOSTNAME':<38} {'VERSÃO':<12} {'CVEs':<35} STATUS\n")
        f.write(f"{'='*16} {'='*6} {'='*38} {'='*12} {'='*35} {'='*20}\n")
    fieldnames = ["IP", "PORTA", "HOSTNAME", "FABRICANTE", "SW_NAME", "SW_VERSAO", "BANNER", "VERSAO_OPENSSH", "CVEs", "STATUS", "TIMESTAMP_UTC"]
    with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames).writeheader()
    log("HEAD", "══════════════════════════════════════════════════════════════════")
    log("INFO", f"Início: {datetime.now()}")
    log("INFO", f"Prefixos: {len(prefixes)}")
    log("INFO", f"Portas SSH: {args.ports}")
    log("INFO", f"Workers SSH: {args.workers}")
    log("INFO", f"Workers DNS: {args.dns_workers}")
    log("INFO", f"Timeout SSH: {args.timeout}s")
    log("INFO", f"Timeout DNS: {args.dns_timeout}s")
    log("INFO", f"Log: {LOG_FILE}")
    log("INFO", f"CSV: {LOG_CSV}")
    log("INFO", f"Saída estruturada: {LOG_CERT}")
    log("INFO", f"Backend DNS: {'dnspython' if HAS_DNSPYTHON else 'socket (fallback)'}")
    log("HEAD", "══════════════════════════════════════════════════════════════════")
    count_vuln = 0
    count_warn = 0
    count_safe = 0
    count_ssh = 0
    start_time = time.time()
    for prefix in prefixes:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            log("WARN", f"Prefixo inválido ignorado: {prefix}")
            continue
        ips = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        log("HEAD", f"[ {prefix} ] — resolvendo DNS de {len(ips)} host(s) ...")
        dns_map = resolve_hostnames_batch(ips)
        scan_targets = [(ip, args.ports) for ip in ips]
        log("HEAD", f"[ {prefix} ] — analisando vulnerabilidades em {len(scan_targets)} host(s) ...")
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(scan_ip_ssh, ip, dns_map.get(ip, "SEM-PTR"), ports, args.timeout): ip
                for ip, ports in scan_targets
            }
            for future in as_completed(futures):
                res = future.result()
                if res is None:
                    continue
                count_ssh += 1
                ip = res["ip"]
                port = res["port"]
                hostname = res["hostname"]
                ver = res["openssh_ver"]
                cves = res["affected_cves"]
                status = res["status"]
                banner = res["banner"]
                cves_str = ";".join(cves) if cves else "—"
                info = f"{ip:<15} | :{port} | {hostname:<33} | {res['fabricante']:<12} | {ver:<10} | {banner}"
                if status == "VULNERÁVEL":
                    log("VULN", f"{info} → [{cves_str}]")
                    with _log_lock:
                        with open(LOG_VULN, "a", encoding="utf-8") as f:
                            f.write(f"{ip:<16} {port:<6} {hostname:<38} {ver:<12} {cves_str:<35} {status}\n")
                        with open(LOG_CERT, "a", newline="", encoding="utf-8") as f:
                            csv.DictWriter(f, fieldnames=["IP", "PORTA", "TIMESTAMP_UTC", "DOMINIO", "FABRICANTE", "SW_NAME", "SW_VERSAO", "CVEs", "BANNER"]).writerow(format_cert_row(res))
                    count_vuln += 1
                elif status in ("VERSÃO-OCULTA", "SSH-NÃO-OPENSSH"):
                    log("WARN", f"{info} → {status}")
                    count_warn += 1
                else:
                    log("OK", f"{info} → {status}")
                    count_safe += 1
                with _log_lock:
                    with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
                        csv.DictWriter(f, fieldnames=fieldnames).writerow({
                            "IP": ip,
                            "PORTA": port,
                            "HOSTNAME": hostname,
                            "FABRICANTE": res["fabricante"],
                            "SW_NAME": res["sw_name"],
                            "SW_VERSAO": res["sw_ver"],
                            "BANNER": banner,
                            "VERSAO_OPENSSH": ver,
                            "CVEs": cves_str,
                            "STATUS": status,
                            "TIMESTAMP_UTC": res["timestamp_utc"],
                        })
    elapsed = int(time.time() - start_time)
    log("HEAD", "══════════════════════════════════════════════════════════════════")
    log("INFO", f"Fim: {datetime.now()}")
    log("INFO", f"Tempo total: {elapsed}s")
    log("INFO", f"Hosts SSH encontrados: {count_ssh}")
    log("INFO", f"Vulneráveis: {count_vuln}")
    log("INFO", f"Avisos: {count_warn}")
    log("INFO", f"Seguros: {count_safe}")
    log("INFO", f"Log completo: {LOG_FILE}")
    log("INFO", f"Lista vulneráv.: {LOG_VULN}")
    log("INFO", f"Resultados CSV: {LOG_CSV}")
    log("INFO", f"Saída estruturada: {LOG_CERT}")
    log("HEAD", "══════════════════════════════════════════════════════════════════")
    # Mostra prévia da saída estruturada no terminal
    if count_vuln > 0:
        print(f"\n {BOLD}{MAGENTA}══ Prévia — Saída Estruturada (top 20) ══{RESET}")
        print(f" {GREY}{'─' * 110}{RESET}")
        print(f" {'IP':<16} | {'Porta':<5} | {'Timestamp (UTC)':<20} | {'Dominio':<35} | {'Fabricante':<12} | {'SW':<12} | {'Versão':<10} | CVEs")
        print(f" {GREY}{'─' * 110}{RESET}")
        try:
            import csv as _csv
            with open(LOG_CERT, "r", encoding="utf-8") as f:
                reader = _csv.DictReader(f)
                rows = list(reader)
                for row in rows[:20]:
                    print(f" {row['IP']:<16} | {row['PORTA']:<5} | {row['TIMESTAMP_UTC']:<20} | {row['DOMINIO']:<35} | {row['FABRICANTE']:<12} | {row['SW_NAME']:<12} | {row['SW_VERSAO']:<10} | {row['CVEs']}")
                if len(rows) > 20:
                    print(f"\n {GREY}... e mais {len(rows)-20} linha(s). Veja o arquivo completo: {LOG_CERT}{RESET}")
        except Exception:
            pass
        print(f" {GREY}{'─' * 110}{RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n Interrompido.")
        sys.exit(0)
