#!/usr/bin/env python3
# byte_reporter.py — Analisador de bytes (hex/bin) com banner e relatório
# Uso:
#   python3 byte_reporter.py --file sample.bin --report report.md --dump
#   python3 byte_reporter.py --hex "4d5a9000..." --report report.md
#   python3 byte_reporter.py --hex-in dump_hex.txt --report report.md --strings

import argparse
import hashlib
import math
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional


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
MAGENTA = "\033[35m"
CYAN = "\033[36m"

def colorize(s: str, c: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"{c}{s}{RESET}"

def banner():
    art = r"""
    ____        __        ____                       __
   / __ )__  __/ /____   / __ \___  ____  ____  _____/ /____  _____
  / __  / / / / __/ _ \ / /_/ / _ \/ __ \/ __ \/ ___/ __/ _ \/ ___/
 / /_/ / /_/ / /_/  __// _, _/  __/ /_/ / /_/ / /  / /_/  __/ /
/_____/\__, /\__/\___//_/ |_|\___/ .___/\____/_/   \__/\___/_/
      /____/                     /_/
"""
    print(colorize(art, CYAN))
    print(colorize("  ByteReporter — análise de hex/bin → bytes → relatório\n", DIM))


# =========================
# Hex parsing / bytes
# =========================

HEX_CLEAN_RE = re.compile(r'(?i)(0x|\\x)')
HEX_ONLY_RE = re.compile(r'^[0-9a-fA-F]*$')

def normalize_hex(s: str) -> str:
    s = HEX_CLEAN_RE.sub("", s)
    s = re.sub(r'[^0-9a-fA-F]', "", s)
    return s

def hex_to_bytes(hex_str: str) -> bytes:
    hex_str = normalize_hex(hex_str)
    if not hex_str:
        raise ValueError("Entrada vazia após normalização (não sobrou hex).")
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Hex inválido: tamanho ímpar ({len(hex_str)}).")
    if not HEX_ONLY_RE.match(hex_str):
        raise ValueError("Hex inválido: contém caracteres fora de 0-9a-f.")
    return bytes.fromhex(hex_str)


# =========================
# Utilitários de análise
# =========================

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    ln = len(data)
    for c in counts:
        if c:
            p = c / ln
            ent -= p * math.log2(p)
    return ent  # 0..8 bits/byte

def byte_frequency_top(data: bytes, topn: int = 10) -> List[Tuple[int, int, float]]:
    if not data:
        return []
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ln = len(data)
    items = [(i, counts[i], counts[i]/ln) for i in range(256) if counts[i] > 0]
    items.sort(key=lambda x: x[1], reverse=True)
    return items[:topn]

def printable_ascii(b: int) -> str:
    return chr(b) if 32 <= b <= 126 else "."

def hexdump(data: bytes, width: int = 16, limit: Optional[int] = None) -> str:
    if limit is not None:
        data = data[:limit]
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{x:02x}" for x in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(printable_ascii(x) for x in chunk)
        lines.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)

def decode_text_views(data: bytes) -> Dict[str, str]:
    # “tradução” dos bytes para texto em diferentes visões
    ascii_view = "".join(printable_ascii(b) for b in data)
    utf8_view = data.decode("utf-8", errors="replace")
    latin1_view = data.decode("latin-1", errors="replace")
    return {
        "ASCII (printable/dot)": ascii_view,
        "UTF-8 (replace)": utf8_view,
        "Latin-1 (replace)": latin1_view,
    }

def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    # pega strings ASCII imprimíveis
    out = []
    cur = []
    for b in data:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out

def guess_filetype(data: bytes) -> List[str]:
    # Heurísticas por magic bytes (bem úteis no relatório)
    sigs = []
    h = data[:32]
    def starts(x: bytes) -> bool:
        return h.startswith(x)

    if starts(b"MZ"):
        sigs.append("PE/EXE (Windows) — magic 'MZ'")
    if starts(b"\x7fELF"):
        sigs.append("ELF (Linux) — magic 0x7F 'ELF'")
    if starts(b"%PDF"):
        sigs.append("PDF — magic '%PDF'")
    if starts(b"\x89PNG\r\n\x1a\n"):
        sigs.append("PNG — magic 89 50 4E 47")
    if starts(b"\xff\xd8\xff"):
        sigs.append("JPEG — magic FF D8 FF")
    if starts(b"GIF87a") or starts(b"GIF89a"):
        sigs.append("GIF — magic 'GIF87a/GIF89a'")
    if starts(b"PK\x03\x04") or starts(b"PK\x05\x06") or starts(b"PK\x07\x08"):
        sigs.append("ZIP / Office / APK (container PK)")
    if starts(b"Rar!\x1a\x07\x00") or starts(b"Rar!\x1a\x07\x01\x00"):
        sigs.append("RAR (archive)")
    if starts(b"\x1f\x8b"):
        sigs.append("GZIP (compressed)")
    if starts(b"7z\xbc\xaf\x27\x1c"):
        sigs.append("7z (archive)")
    if starts(b"OggS"):
        sigs.append("OGG (audio/container)")
    if starts(b"ID3"):
        sigs.append("MP3 (ID3 tag)")
    if not sigs:
        sigs.append("Desconhecido (sem assinatura óbvia nos primeiros bytes)")
    return sigs


# =========================
# Relatório
# =========================

def build_report(
    data: bytes,
    source_label: str,
    include_dump: bool,
    dump_width: int,
    dump_limit: Optional[int],
    include_strings: bool,
    strings_min: int,
    strings_limit: int,
    include_text_views: bool,
    text_view_limit: int,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    size = len(data)
    ent = entropy(data)
    sigs = guess_filetype(data)
    top = byte_frequency_top(data, topn=10)

    lines = []
    lines.append(f"# ByteReporter — Relatório\n")
    lines.append(f"- **Gerado em:** `{now}`")
    lines.append(f"- **Fonte:** `{source_label}`")
    lines.append(f"- **Tamanho:** `{size}` bytes")
    lines.append(f"- **MD5:** `{md5(data)}`")
    lines.append(f"- **SHA-256:** `{sha256(data)}`")
    lines.append(f"- **Entropia (Shannon):** `{ent:.4f}` bits/byte  _(0 a 8; alto pode indicar compressão/criptografia)_")
    lines.append("")
    lines.append("## Assinatura / Tipo provável")
    for s in sigs:
        lines.append(f"- {s}")
    lines.append("")

    lines.append("## Frequência de bytes (Top 10)")
    lines.append("| Byte (hex) | Contagem | Percentual |")
    lines.append("|---|---:|---:|")
    for b, c, p in top:
        lines.append(f"| `0x{b:02X}` | {c} | {p*100:.2f}% |")
    lines.append("")

    if include_text_views:
        lines.append("## “Tradução” dos bytes para texto (visões)")
        views = decode_text_views(data[:text_view_limit])
        lines.append(f"_Mostrando até `{text_view_limit}` bytes para evitar relatório gigante._\n")
        for k, v in views.items():
            lines.append(f"### {k}")
            # evitar quebrar markdown com ``` dentro do texto
            safe = v.replace("```", "` ` `")
            lines.append("```")
            lines.append(safe)
            lines.append("```")
        lines.append("")

    if include_strings:
        lines.append("## Strings ASCII encontradas")
        strs = extract_strings(data, min_len=strings_min)
        lines.append(f"- **Min len:** `{strings_min}`")
        lines.append(f"- **Encontradas:** `{len(strs)}` (mostrando até `{strings_limit}`)\n")
        for s in strs[:strings_limit]:
            # encurta strings enormes
            if len(s) > 200:
                s = s[:200] + "…"
            lines.append(f"- `{s}`")
        lines.append("")

    if include_dump:
        lines.append("## Hexdump")
        if dump_limit is None:
            lines.append("_Mostrando arquivo completo._\n")
        else:
            lines.append(f"_Mostrando apenas os primeiros `{dump_limit}` bytes._\n")
        lines.append("```")
        lines.append(hexdump(data, width=dump_width, limit=dump_limit))
        lines.append("```")
        lines.append("")

    # Pequeno “diagnóstico” para leitura rápida
    lines.append("## Observações rápidas")
    if ent >= 7.2:
        lines.append("- Entropia alta: **pode** ser conteúdo comprimido/criptografado ou binário denso.")
    elif ent <= 5.0:
        lines.append("- Entropia baixa/moderada: tende a ter mais estrutura/repetição (texto, formatos simples, padding).")
    else:
        lines.append("- Entropia intermediária: pode ser mistura (cabeçalhos + dados).")

    if size >= 50_000_000:
        lines.append("- Arquivo grande: para relatório rápido, use `--dump-limit` e `--text-limit`.")
    lines.append("")
    return "\n".join(lines)


# =========================
# Main CLI
# =========================

def main():
    banner()

    ap = argparse.ArgumentParser(
        description="Converte HEX/BIN em bytes e gera relatório bonito (md/txt) + hexdump/strings/text views."
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Arquivo binário para analisar (ex: sample.bin).")
    src.add_argument("--hex", help="Hex direto (ex: '41 42 43' ou '\\x41\\x42').")
    src.add_argument("--hex-in", help="Arquivo texto contendo hex em qualquer formatação.")

    ap.add_argument("--report", required=True, help="Caminho do relatório de saída (.md recomendado).")

    ap.add_argument("--dump", action="store_true", help="Inclui hexdump no relatório.")
    ap.add_argument("--width", type=int, default=16, help="Bytes por linha no hexdump (padrão 16).")
    ap.add_argument("--dump-limit", type=int, default=4096, help="Limite de bytes no hexdump (padrão 4096). Use 0 para completo.")

    ap.add_argument("--text", action="store_true", help="Inclui ‘tradução’ para texto (ASCII/UTF-8/Latin1).")
    ap.add_argument("--text-limit", type=int, default=4096, help="Limite de bytes para as visões de texto (padrão 4096).")

    ap.add_argument("--strings", action="store_true", help="Extrai strings ASCII e inclui no relatório.")
    ap.add_argument("--min-string", type=int, default=4, help="Tamanho mínimo de string (padrão 4).")
    ap.add_argument("--strings-limit", type=int, default=200, help="Máximo de strings listadas (padrão 200).")

    ap.add_argument("--out-bin", help="Opcional: salva os bytes em um arquivo .bin (útil se veio de HEX).")

    args = ap.parse_args()

    try:
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
            source_label = f"file:{args.file}"

        elif args.hex is not None:
            data = hex_to_bytes(args.hex)
            source_label = "hex:stdin"

        else:
            with open(args.hex_in, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            data = hex_to_bytes(raw)
            source_label = f"hexfile:{args.hex_in}"

        if args.out_bin:
            with open(args.out_bin, "wb") as f:
                f.write(data)
            print(colorize(f"[+] bytes exportados: {args.out_bin} ({len(data)} bytes)", GREEN))

        dump_limit = None if args.dump_limit == 0 else args.dump_limit

        report_text = build_report(
            data=data,
            source_label=source_label,
            include_dump=args.dump,
            dump_width=max(1, args.width),
            dump_limit=dump_limit,
            include_strings=args.strings,
            strings_min=max(1, args.min_string),
            strings_limit=max(1, args.strings_limit),
            include_text_views=args.text,
            text_view_limit=max(1, args.text_limit),
        )

        # garante pasta
        os.makedirs(os.path.dirname(os.path.abspath(args.report)) or ".", exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report_text)

        print(colorize(f"[+] relatório gerado: {args.report}", GREEN))
        print(colorize(f"[+] tamanho analisado: {len(data)} bytes", BLUE))

        # resumo rápido no terminal
        print(colorize("\nResumo rápido:", BOLD))
        print(f"  - SHA-256: {sha256(data)}")
        print(f"  - Entropia: {entropy(data):.4f} bits/byte")
        print(f"  - Tipo provável: {', '.join(guess_filetype(data))}")

    except Exception as e:
        print(colorize(f"[!] erro: {e}", RED), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
