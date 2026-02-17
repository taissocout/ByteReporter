#!/usr/bin/env python3
# ByteReporter v2 — Decodifica HEX/BIN e explica Ethernet/IP/TCP/HTTP de forma leiga
#
# - Se o arquivo for "bytes.txt" com "d4 ab 82 ...", ele detecta e converte HEX -> bytes.
# - Se for binário real, ele analisa como bytes direto.
# - Tenta parsear: Ethernet -> IPv4 -> TCP -> payload -> HTTP.
#
# Uso:
#   python3 byte_reporter.py           (interativo)
#   python3 byte_reporter.py --file bytes.txt --report report.md
#
# Autor: Taisso Coutinho

import argparse
import hashlib
import math
import os
import re
import sys
from datetime import datetime
from typing import Optional, Tuple, Dict, List


# =========================
# Estética (banner + cores)
# =========================

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"

def is_tty() -> bool:
    return sys.stdout.isatty()

def c(s: str, color: str) -> str:
    if not is_tty():
        return s
    return f"{color}{s}{RESET}"

def banner():
    art = r"""
    ____        __        ____                       __
   / __ )__  __/ /____   / __ \___  ____  ____  _____/ /____  _____
  / __  / / / / __/ _ \ / /_/ / _ \/ __ \/ __ \/ ___/ __/ _ \/ ___/
 / /_/ / /_/ / /_/  __// _, _/  __/ /_/ / /_/ / /  / /_/  __/ /
/_____/\__, /\__/\___//_/ |_|\___/ .___/\____/_/   \__/\___/_/
      /____/                     /_/
"""
    print(c(art, CYAN))
    print(c("  ByteReporter v2 — HEX/BIN → Ethernet/IP/TCP/HTTP → relatório leigo\n", DIM))


# =========================
# Hex helpers
# =========================

HEX_CLEAN_RE = re.compile(r'(?i)(0x|\\x)')
HEX_PAIR_RE = re.compile(r'(?i)\b[0-9a-f]{2}\b')

def normalize_hex_text(s: str) -> str:
    # remove 0x e \x, mantém apenas hex e separadores
    s = HEX_CLEAN_RE.sub("", s)
    # troca qualquer coisa não-hex por espaço (preserva pares)
    s = re.sub(r'[^0-9a-fA-F]', ' ', s)
    # normaliza espaços
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def hex_text_to_bytes(s: str) -> bytes:
    # extrai pares hex e converte
    pairs = HEX_PAIR_RE.findall(s)
    if not pairs:
        raise ValueError("Não encontrei pares HEX (ex: '4d', 'ff', '0a') no texto.")
    return bytes(int(p, 16) for p in pairs)

def looks_like_hex_text(raw: bytes) -> bool:
    """
    Heurística: se o arquivo é "texto" e contém muitos pares hex, provavelmente é dump hex.
    """
    try:
        txt = raw.decode("utf-8", errors="ignore")
    except Exception:
        return False
    pairs = HEX_PAIR_RE.findall(txt)
    # se tem muitos pares e pouco lixo, consideramos hex-text
    if len(pairs) >= 16:  # mínimo para caber headers
        # se a maioria do conteúdo são hex/espacos
        cleaned = normalize_hex_text(txt)
        # se após normalizar ainda há pares suficientes
        return len(HEX_PAIR_RE.findall(cleaned)) >= 16
    return False


# =========================
# Byte analysis utilities
# =========================

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    ln = len(data)
    for c_ in counts:
        if c_:
            p = c_ / ln
            ent -= p * math.log2(p)
    return ent

def printable_ascii(b: int) -> str:
    return chr(b) if 32 <= b <= 126 else "."

def hexdump(data: bytes, width: int = 16, limit: Optional[int] = 512) -> str:
    if limit is not None:
        data = data[:limit]
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{x:02x}" for x in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(printable_ascii(x) for x in chunk)
        lines.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


# =========================
# Parsers: Ethernet / IPv4 / TCP / HTTP
# =========================

def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

def ip_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)

def u16(b: bytes) -> int:
    return (b[0] << 8) | b[1]

def u32(b: bytes) -> int:
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]

TCP_FLAG_NAMES = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

def parse_ethernet(data: bytes) -> Optional[Dict]:
    if len(data) < 14:
        return None
    dst = data[0:6]
    src = data[6:12]
    ethertype = u16(data[12:14])
    return {
        "dst_mac": mac_str(dst),
        "src_mac": mac_str(src),
        "ethertype": ethertype,
        "payload": data[14:],
    }

def parse_ipv4(data: bytes) -> Optional[Dict]:
    if len(data) < 20:
        return None
    v_ihl = data[0]
    version = (v_ihl >> 4) & 0x0F
    ihl = (v_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return None

    total_len = u16(data[2:4])
    proto = data[9]
    src = data[12:16]
    dst = data[16:20]

    # garante limites
    if total_len == 0 or total_len > len(data):
        total_len = len(data)

    return {
        "version": version,
        "ihl": ihl,
        "total_len": total_len,
        "protocol": proto,
        "src_ip": ip_str(src),
        "dst_ip": ip_str(dst),
        "payload": data[ihl:total_len],
    }

def parse_tcp(data: bytes) -> Optional[Dict]:
    if len(data) < 20:
        return None
    src_port = u16(data[0:2])
    dst_port = u16(data[2:4])
    seq = u32(data[4:8])
    ack = u32(data[8:12])
    doff = (data[12] >> 4) & 0x0F
    hdr_len = doff * 4
    if hdr_len < 20 or len(data) < hdr_len:
        return None
    flags = data[13]
    win = u16(data[14:16])

    flag_list = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "header_len": hdr_len,
        "flags": flag_list,
        "window": win,
        "payload": data[hdr_len:],
    }

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")

def parse_http(payload: bytes) -> Optional[Dict]:
    # Heurística simples para HTTP request
    if not payload:
        return None
    if not any(payload.startswith(m) for m in HTTP_METHODS) and not payload.startswith(b"HTTP/"):
        return None

    # tenta decodificar como texto
    text = payload.decode("utf-8", errors="replace")
    # separa header/body
    parts = text.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_block.split("\r\n")
    first = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    info = {"first_line": first, "headers": headers, "body": body}
    # tenta extrair método/path/versão
    if " " in first:
        toks = first.split(" ")
        if len(toks) >= 3:
            info["method"] = toks[0]
            info["path"] = toks[1]
            info["version"] = toks[2]
    return info


# =========================
# “Explicação leiga”
# =========================

def explain_for_layman(layers: Dict) -> str:
    """
    Texto curto e claro explicando o que foi encontrado.
    """
    lines = []
    lines.append("## Explicação para leigos (o que isso significa)\n")

    if "ethernet" in layers:
        e = layers["ethernet"]
        lines.append("- Isso parece ser um **quadro Ethernet** (tráfego de rede local).")
        lines.append(f"  - **MAC origem**: `{e['src_mac']}` (quem enviou na rede local)")
        lines.append(f"  - **MAC destino**: `{e['dst_mac']}` (para quem foi na rede local)")
        lines.append("")

    if "ipv4" in layers:
        ip = layers["ipv4"]
        lines.append("- Dentro dele existe um **pacote IPv4** (endereço IP).")
        lines.append(f"  - **IP origem**: `{ip['src_ip']}` (quem enviou)")
        lines.append(f"  - **IP destino**: `{ip['dst_ip']}` (quem recebeu)")
        lines.append("")

    if "tcp" in layers:
        t = layers["tcp"]
        lines.append("- Dentro do IP existe **TCP** (conexão parecida com 'chamada' confiável).")
        lines.append(f"  - **Porta origem**: `{t['src_port']}` (porta de saída do cliente)")
        lines.append(f"  - **Porta destino**: `{t['dst_port']}` (porta do serviço, ex: 80/443)")
        lines.append(f"  - **Flags**: `{', '.join(t['flags']) if t['flags'] else 'nenhuma'}` (o que esse segmento está fazendo)")
        lines.append("")

    if "http" in layers:
        h = layers["http"]
        lines.append("- O **conteúdo (payload)** parece ser **HTTP** (site / web).")
        if "method" in h:
            lines.append(f"  - **Requisição**: `{h.get('method','')} {h.get('path','')} {h.get('version','')}`")
        host = h.get("headers", {}).get("Host")
        ua = h.get("headers", {}).get("User-Agent")
        if host:
            lines.append(f"  - **Host (site)**: `{host}`")
        if ua:
            lines.append(f"  - **User-Agent**: `{ua}` (navegador/cliente)")
        lines.append("")
    else:
        # se tiver payload mas não é http
        payload = layers.get("payload_bytes", b"")
        if payload:
            lines.append("- Existe um **payload** (conteúdo) que não parece HTTP pela heurística.")
            lines.append("  - Pode ser outro protocolo, ou dados binários.")
            lines.append("")

    return "\n".join(lines)


# =========================
# Análise principal (detectar camadas)
# =========================

def analyze_layers(data: bytes) -> Dict:
    """
    Tenta detectar camadas:
    - Ethernet (ethertype 0x0800 -> IPv4)
    - IPv4 (protocol 6 -> TCP)
    - TCP -> payload -> HTTP
    """
    layers: Dict = {}

    eth = parse_ethernet(data)
    cursor = data

    if eth and eth["ethertype"] == 0x0800:  # IPv4
        layers["ethernet"] = {
            "src_mac": eth["src_mac"],
            "dst_mac": eth["dst_mac"],
            "ethertype": eth["ethertype"],
        }
        cursor = eth["payload"]
    else:
        # talvez não tenha ethernet (pode ser só IP)
        cursor = data

    ip = parse_ipv4(cursor)
    if ip:
        layers["ipv4"] = {
            "src_ip": ip["src_ip"],
            "dst_ip": ip["dst_ip"],
            "protocol": ip["protocol"],
            "ihl": ip["ihl"],
            "total_len": ip["total_len"],
        }
        cursor = ip["payload"]
    else:
        cursor = cursor

    # TCP
    if "ipv4" in layers and layers["ipv4"]["protocol"] == 6:
        tcp = parse_tcp(cursor)
        if tcp:
            layers["tcp"] = {
                "src_port": tcp["src_port"],
                "dst_port": tcp["dst_port"],
                "seq": tcp["seq"],
                "ack": tcp["ack"],
                "flags": tcp["flags"],
                "window": tcp["window"],
                "header_len": tcp["header_len"],
            }
            payload = tcp["payload"]
            layers["payload_bytes"] = payload
            http = parse_http(payload)
            if http:
                layers["http"] = http
        else:
            # não conseguiu parsear tcp
            layers["payload_bytes"] = cursor
    else:
        # sem IP/TCP detectado: trata resto como payload
        layers["payload_bytes"] = cursor

    return layers


# =========================
# Relatório (leigo + técnico)
# =========================

def build_report(
    source_label: str,
    bytes_source_kind: str,
    data: bytes,
    layers: Dict,
    dump_limit: int = 1024,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ent = entropy(data)

    payload = layers.get("payload_bytes", b"")
    payload_text = payload.decode("utf-8", errors="replace") if payload else ""

    lines: List[str] = []
    lines.append("# ByteReporter — Relatório\n")
    lines.append(f"- **Gerado em:** `{now}`")
    lines.append(f"- **Fonte:** `{source_label}`")
    lines.append(f"- **Como os bytes foram interpretados:** `{bytes_source_kind}`")
    lines.append(f"- **Tamanho (bytes reais):** `{len(data)}` bytes")
    lines.append(f"- **MD5:** `{md5(data)}`")
    lines.append(f"- **SHA-256:** `{sha256(data)}`")
    lines.append(f"- **Entropia (Shannon):** `{ent:.4f}` bits/byte")
    lines.append("")

    # Leigo
    lines.append(explain_for_layman(layers))

    # Técnico organizado
    lines.append("## Decodificação organizada (técnico, mas claro)\n")

    if "ethernet" in layers:
        e = layers["ethernet"]
        lines.append("### Camada 2 — Ethernet (rede local)")
        lines.append(f"- **MAC origem:** `{e['src_mac']}`")
        lines.append(f"- **MAC destino:** `{e['dst_mac']}`")
        lines.append(f"- **EtherType:** `0x{e['ethertype']:04x}` (0800 = IPv4)")
        lines.append("")

    if "ipv4" in layers:
        ip = layers["ipv4"]
        proto = ip["protocol"]
        proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto))
        lines.append("### Camada 3 — IPv4")
        lines.append(f"- **IP origem:** `{ip['src_ip']}`")
        lines.append(f"- **IP destino:** `{ip['dst_ip']}`")
        lines.append(f"- **Protocolo:** `{proto}` ({proto_name})")
        lines.append(f"- **IHL (tamanho do header):** `{ip['ihl']}` bytes")
        lines.append(f"- **Total Length (tamanho do pacote IP):** `{ip['total_len']}` bytes")
        lines.append("")

    if "tcp" in layers:
        t = layers["tcp"]
        lines.append("### Camada 4 — TCP")
        lines.append(f"- **Porta origem:** `{t['src_port']}`")
        lines.append(f"- **Porta destino:** `{t['dst_port']}`")
        lines.append(f"- **SEQ:** `{t['seq']}`")
        lines.append(f"- **ACK:** `{t['ack']}`")
        lines.append(f"- **Flags:** `{', '.join(t['flags']) if t['flags'] else 'nenhuma'}`")
        lines.append(f"- **Window:** `{t['window']}`")
        lines.append(f"- **Header Length:** `{t['header_len']}` bytes")
        lines.append("")

    # Payload
    lines.append("### Payload (conteúdo transportado)")
    lines.append(f"- **Tamanho do payload:** `{len(payload)}` bytes")
    if "http" in layers:
        h = layers["http"]
        lines.append("- **Tipo detectado:** `HTTP`")
        lines.append("")
        lines.append("#### HTTP (interpretado)")
        lines.append(f"- **Linha inicial:** `{h.get('first_line','')}`")
        if "method" in h:
            lines.append(f"- **Método:** `{h.get('method','')}`")
            lines.append(f"- **Caminho:** `{h.get('path','')}`")
            lines.append(f"- **Versão:** `{h.get('version','')}`")
        lines.append("")
        lines.append("#### Headers")
        headers = h.get("headers", {})
        if headers:
            for k in sorted(headers.keys()):
                lines.append(f"- **{k}:** `{headers[k]}`")
        else:
            lines.append("- (nenhum header parseado)")
        lines.append("")
        if h.get("body"):
            lines.append("#### Body (primeiros 800 chars)")
            body = h["body"]
            if len(body) > 800:
                body = body[:800] + "…"
            lines.append("```")
            lines.append(body.replace("```", "` ` `"))
            lines.append("```")
            lines.append("")
    else:
        lines.append("- **Tipo detectado:** `não identificado (pode ser binário/outro protocolo)`")
        lines.append("")

    # “Tradução” payload para texto (o que você queria: 0x41 -> 'A')
    if payload:
        lines.append("#### Payload em texto (UTF-8 com substituição)")
        # limita para não explodir relatório
        show = payload_text
        if len(show) > 2000:
            show = show[:2000] + "…"
        lines.append("```")
        lines.append(show.replace("```", "` ` `"))
        lines.append("```")
        lines.append("")

    # hexdump dos bytes reais
    lines.append("## Hexdump (bytes reais)")
    lines.append(f"_Mostrando os primeiros `{dump_limit}` bytes._\n")
    lines.append("```")
    lines.append(hexdump(data, limit=dump_limit))
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


# =========================
# Interativo
# =========================

def prompt_yes_no(q: str, default: bool = True) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        ans = input(c(q, BOLD) + suffix).strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes", "s", "sim"):
            return True
        if ans in ("n", "no", "nao", "não"):
            return False
        print(c("Resposta inválida. Digite y/n.", YELLOW))

def interactive() -> None:
    banner()
    print(c("Modo interativo.\n", GREEN))
    print(c("Dica: coloque o arquivo no MESMO diretório onde você roda o script.\n", DIM))

    # arquivo
    while True:
        fname = input(c("Nome do arquivo para analisar (ex: bytes.txt): ", BOLD)).strip()
        if not fname:
            print(c("Nome vazio.", YELLOW))
            continue
        if os.path.sep in fname:
            print(c("Use apenas o nome do arquivo (sem caminho).", YELLOW))
            continue
        if not os.path.isfile(fname):
            print(c(f"Arquivo '{fname}' não encontrado aqui. Rode 'ls' e confira.", RED))
            continue
        break

    with open(fname, "rb") as f:
        raw = f.read()

    # detectar se é hex-text
    auto_hex = looks_like_hex_text(raw)
    if auto_hex:
        print(c("\n[+] Detectei que o arquivo parece ser HEX em texto (ex: 'd4 ab 82 ...').", GREEN))
        use_hex = True
    else:
        print(c("\n[+] O arquivo parece binário (bytes reais).", GREEN))
        use_hex = False

    if prompt_yes_no("Quer forçar interpretação como HEX-text?", default=use_hex):
        use_hex = True

    if use_hex:
        txt = raw.decode("utf-8", errors="ignore")
        data = hex_text_to_bytes(txt)
        kind = "hex-text -> bytes (conversão feita)"
    else:
        data = raw
        kind = "binário -> bytes (direto)"

    layers = analyze_layers(data)

    report_name = input(c("Nome do relatório [report.md]: ", BOLD)).strip() or "report.md"
    if not report_name.lower().endswith((".md", ".txt")):
        report_name += ".md"

    dump_limit = 1024
    try:
        dump_limit = int(input(c("Hexdump: quantos bytes mostrar? [1024]: ", BOLD)).strip() or "1024")
        if dump_limit <= 0:
            dump_limit = 1024
    except Exception:
        dump_limit = 1024

    report = build_report(
        source_label=f"file:{fname}",
        bytes_source_kind=kind,
        data=data,
        layers=layers,
        dump_limit=dump_limit,
    )

    with open(report_name, "w", encoding="utf-8") as f:
        f.write(report)

    print(c(f"\n[+] Relatório gerado: {report_name}", GREEN))

    # resumo no terminal
    ip = layers.get("ipv4", {})
    tcp = layers.get("tcp", {})
    if ip:
        print(c("[Resumo] IP origem/destino:", BLUE), ip.get("src_ip"), "->", ip.get("dst_ip"))
    if tcp:
        print(c("[Resumo] TCP portas:", BLUE), tcp.get("src_port"), "->", tcp.get("dst_port"))
    if "http" in layers:
        h = layers["http"]
        print(c("[Resumo] HTTP:", BLUE), h.get("first_line",""))
    print(c("\nFinalizado ✅", GREEN))


# =========================
# CLI
# =========================

def parse_args():
    ap = argparse.ArgumentParser(description="ByteReporter v2 — HEX/BIN -> Ethernet/IP/TCP/HTTP (relatório leigo).")
    ap.add_argument("--file", help="Arquivo no diretório atual (ex: bytes.txt).")
    ap.add_argument("--report", default="report.md", help="Nome do relatório (padrão report.md).")
    ap.add_argument("--force-hex", action="store_true", help="Força interpretar arquivo como HEX-text.")
    ap.add_argument("--dump-limit", type=int, default=1024, help="Quantos bytes mostrar no hexdump.")
    return ap.parse_args()

def main():
    args = parse_args()

    # se não passou --file, entra no modo interativo
    if not args.file:
        interactive()
        return

    banner()

    if os.path.sep in args.file:
        print(c("[!] Use apenas o nome do arquivo (sem caminho).", RED), file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.file):
        print(c(f"[!] Arquivo '{args.file}' não encontrado no diretório atual.", RED), file=sys.stderr)
        sys.exit(1)

    with open(args.file, "rb") as f:
        raw = f.read()

    use_hex = args.force_hex or looks_like_hex_text(raw)

    if use_hex:
        txt = raw.decode("utf-8", errors="ignore")
        data = hex_text_to_bytes(txt)
        kind = "hex-text -> bytes (conversão feita)"
        print(c("[+] Interpretando como HEX-text e convertendo para bytes reais.", GREEN))
    else:
        data = raw
        kind = "binário -> bytes (direto)"
        print(c("[+] Interpretando como binário (bytes reais).", GREEN))

    layers = analyze_layers(data)

    report = build_report(
        source_label=f"file:{args.file}",
        bytes_source_kind=kind,
        data=data,
        layers=layers,
        dump_limit=max(64, args.dump_limit),
    )

    if not args.report.lower().endswith((".md", ".txt")):
        args.report += ".md"

    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report)

    print(c(f"[+] Relatório gerado: {args.report}", GREEN))


if __name__ == "__main__":
    main()
