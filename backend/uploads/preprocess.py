"""File preprocessing: detect type and produce a lightweight summary for LLM prompts."""
from __future__ import annotations
import logging
import re
import struct
import tarfile
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)

SOURCE_EXTS = {
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs",
    ".go", ".rs", ".java", ".kt", ".swift",
    ".rb", ".php", ".cs", ".scala",
    ".sh", ".bash", ".zsh", ".fish",
    ".html", ".css", ".vue", ".svelte",
    ".json", ".yaml", ".yml", ".toml", ".xml",
    ".sql", ".proto", ".graphql",
    ".md", ".rst", ".txt",
}

BINARY_EXTS = {".bin", ".exe", ".dll", ".so", ".dylib", ".o", ".out", ".elf"}
PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".bz2", ".tbz2", ".xz", ".7z", ".rar"}

# Printable ASCII + common whitespace
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e\t\n\r]{6,}")


def classify(filename: str, content_head: bytes) -> str:
    """Return one of: source, binary, pcap, archive, other."""
    name = filename.lower()

    if name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return "archive"
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""

    # PCAP magic
    if len(content_head) >= 4:
        magic = content_head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
            return "pcap"

    # ELF / PE / Mach-O
    if content_head.startswith(b"\x7fELF"):
        return "binary"
    if content_head.startswith(b"MZ"):
        return "binary"
    if content_head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                             b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "binary"

    # PDF / legacy Office
    if content_head.startswith(b"%PDF"):
        return "document"
    if content_head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "document"
    if ext in {".pdf", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx",
               ".odt", ".ods", ".odp", ".rtf"}:
        return "document"

    # ZIP / GZIP / 7z / RAR / XZ / BZIP2
    if content_head.startswith(b"PK\x03\x04") or content_head.startswith(b"PK\x05\x06"):
        return "archive"
    if content_head.startswith(b"\x1f\x8b"):
        return "archive"
    if content_head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "archive"
    if content_head.startswith(b"Rar!"):
        return "archive"
    if content_head.startswith(b"\xfd7zXZ"):
        return "archive"
    if content_head.startswith(b"BZh"):
        return "archive"
    # uncompressed tar: "ustar" at offset 257
    if len(content_head) >= 265 and content_head[257:262] == b"ustar":
        return "archive"

    if ext in PCAP_EXTS:
        return "pcap"
    if ext in BINARY_EXTS:
        return "binary"
    if ext in ARCHIVE_EXTS:
        return "archive"
    if ext in SOURCE_EXTS:
        return "source"

    # Heuristic: mostly-printable => treat as source/text
    sample = content_head[:2048]
    if sample:
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
        if printable / len(sample) > 0.85:
            return "source"

    return "other"


def _read_head(path: Path, n: int = 4096) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(n)
    except Exception:
        return b""


def _summarize_source(path: Path, size: int) -> dict:
    # Embed up to 64 KB of source verbatim — for typical small files the LLM
    # gets the entire content, not just an 80-line snippet. The text is later
    # rendered into the prompt by render_for_prompt().
    MAX_EMBED = 64 * 1024
    try:
        data = path.read_bytes()[:MAX_EMBED]
    except Exception as e:
        return {"error": f"read failed: {e}"}
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    truncated = size > MAX_EMBED
    return {
        "total_size": size,
        "embedded_bytes": len(data),
        "truncated": truncated,
        "content": text,
    }


def _summarize_binary(path: Path, size: int) -> dict:
    head = _read_head(path, 8192)
    arch = "unknown"
    fmt = "unknown"
    if head.startswith(b"\x7fELF"):
        fmt = "ELF"
        if len(head) >= 20:
            ei_class = head[4]   # 1=32, 2=64
            ei_data = head[5]    # 1=LE, 2=BE
            e_machine = struct.unpack("<H" if ei_data == 1 else ">H", head[18:20])[0]
            machines = {0x03: "x86", 0x3e: "x86_64", 0x28: "arm", 0xb7: "aarch64",
                        0xf3: "riscv", 0x08: "mips"}
            bits = "64" if ei_class == 2 else "32"
            arch = f"{machines.get(e_machine, 'em_' + hex(e_machine))}/{bits}bit"
    elif head.startswith(b"MZ"):
        fmt = "PE"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                       b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        fmt = "Mach-O"

    strings: list[str] = []
    try:
        with path.open("rb") as f:
            data = f.read(256 * 1024)
        for m in _PRINTABLE_RE.finditer(data):
            s = m.group().decode("ascii", errors="replace").strip()
            if 6 <= len(s) <= 120:
                strings.append(s)
            if len(strings) >= 40:
                break
    except Exception as e:
        strings = [f"(strings extraction failed: {e})"]

    return {
        "total_size": size,
        "format": fmt,
        "arch": arch,
        "strings_sample": strings[:40],
    }


def _summarize_pcap(path: Path, size: int) -> dict:
    head = _read_head(path, 64)
    fmt = "unknown"
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        fmt = "pcap"
    elif head[:4] in (b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\xb2\xa1"):
        fmt = "pcapng"
    return {
        "total_size": size,
        "format": fmt,
        "note": "load into Wireshark/tshark for deep parsing",
    }


_TEXT_EXTS_IN_ARCHIVE = {
    "md", "txt", "rst", "log", "csv", "tsv",
    "json", "yaml", "yml", "toml", "ini", "conf", "env", "xml", "html",
    "py", "c", "cc", "cpp", "cxx", "h", "hpp",
    "go", "rs", "js", "jsx", "ts", "tsx", "mjs",
    "java", "kt", "scala", "rb", "php", "cs",
    "sh", "bash", "zsh", "fish",
    "sql", "proto", "graphql", "vue", "svelte",
}


def _summarize_archive(path: Path, size: int) -> dict:
    manifest: list[dict] = []
    text_previews: dict[str, str] = {}
    entry_cap = 200
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist()[:entry_cap]:
                    manifest.append({
                        "name": info.filename,
                        "size": info.file_size,
                        "is_dir": info.is_dir(),
                    })
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > 32 * 1024:
                        continue
                    if info.filename.lower().rsplit(".", 1)[-1] in _TEXT_EXTS_IN_ARCHIVE:
                        try:
                            raw = zf.read(info).decode("utf-8", errors="replace")
                            text_previews[info.filename] = raw[:4000]
                        except Exception:
                            pass
                    if len(text_previews) >= 8:
                        break
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                members = tf.getmembers()[:entry_cap]
                for m in members:
                    manifest.append({
                        "name": m.name,
                        "size": m.size,
                        "is_dir": m.isdir(),
                    })
                for m in members:
                    if not m.isfile() or m.size > 32 * 1024:
                        continue
                    if m.name.lower().rsplit(".", 1)[-1] in _TEXT_EXTS_IN_ARCHIVE:
                        try:
                            f = tf.extractfile(m)
                            if f:
                                text_previews[m.name] = f.read().decode("utf-8", errors="replace")[:4000]
                        except Exception:
                            pass
                    if len(text_previews) >= 8:
                        break
        else:
            return {"total_size": size, "note": "unrecognized archive (kept as blob)"}
    except Exception as e:
        log.warning("archive summary failed for %s: %s", path, e)
        return {"total_size": size, "error": f"archive summary failed: {e}"}

    return {
        "total_size": size,
        "entry_count": len(manifest),
        "manifest": manifest[:50],
        "text_previews": text_previews,
    }


def _summarize_document(path: Path, filename: str, size: int) -> dict:
    """Extract text from PDF / Office docs. Falls back to metadata if extraction unavailable."""
    name = filename.lower()
    MAX_EMBED = 64 * 1024
    text = ""
    method = "none"

    if name.endswith(".pdf") or _read_head(path, 4) == b"%PDF":
        # Try pypdf if installed
        try:
            from pypdf import PdfReader  # type: ignore
            reader = PdfReader(str(path))
            chunks: list[str] = []
            total = 0
            for page in reader.pages:
                t = (page.extract_text() or "").strip()
                if t:
                    chunks.append(t)
                    total += len(t)
                if total > MAX_EMBED:
                    break
            text = "\n\n".join(chunks)[:MAX_EMBED]
            method = "pypdf"
        except ImportError:
            method = "pypdf-missing"
        except Exception as e:
            method = f"pypdf-error:{type(e).__name__}"
    elif name.endswith((".docx", ".xlsx", ".pptx", ".odt")):
        try:
            import zipfile as _zip
            import re as _re
            with _zip.ZipFile(path) as zf:
                parts: list[str] = []
                for n in zf.namelist():
                    if n.endswith(".xml") and ("document" in n or "sheet" in n
                                                or "slide" in n or "content" in n):
                        try:
                            xml = zf.read(n).decode("utf-8", errors="replace")
                            stripped = _re.sub(r"<[^>]+>", " ", xml)
                            stripped = _re.sub(r"\s+", " ", stripped).strip()
                            if stripped:
                                parts.append(stripped)
                        except Exception:
                            pass
                text = ("\n\n".join(parts))[:MAX_EMBED]
                method = "office-xml-strip"
        except Exception as e:
            method = f"office-error:{type(e).__name__}"

    truncated = len(text.encode("utf-8")) >= MAX_EMBED
    return {
        "total_size": size,
        "embedded_bytes": len(text.encode("utf-8")),
        "method": method,
        "truncated": truncated,
        "content": text,
    }


def _summarize_other(path: Path, size: int) -> dict:
    """For unknown types, try treating as text. Fall back to a hex preview."""
    MAX_EMBED = 64 * 1024
    try:
        data = path.read_bytes()[:MAX_EMBED]
    except Exception as e:
        return {"error": f"read failed: {e}"}
    # Heuristic: mostly-printable => embed as text
    sample = data[:4096]
    if sample:
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7e
                        or b in (0x09, 0x0a, 0x0d))
        if printable / len(sample) > 0.85:
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = ""
            return {
                "total_size": size,
                "embedded_bytes": len(data),
                "truncated": size > MAX_EMBED,
                "content": text,
                "method": "text-embed",
            }
    # Otherwise show a hex preview of the head
    hex_preview = data[:512].hex(" ", 16)
    return {
        "total_size": size,
        "method": "hex-preview",
        "hex_preview": hex_preview,
    }


def summarize(path: Path, filename: str, size: int, file_type: str) -> dict:
    if file_type == "source":
        return _summarize_source(path, size)
    if file_type == "binary":
        return _summarize_binary(path, size)
    if file_type == "pcap":
        return _summarize_pcap(path, size)
    if file_type == "archive":
        return _summarize_archive(path, size)
    if file_type == "document":
        return _summarize_document(path, filename, size)
    return _summarize_other(path, size)


def render_for_prompt(uf) -> str:
    """Render an UploadedFile into a Markdown block embedded in the LLM prompt.

    The block contains the actual file content (for source/archive text) so
    the LLM never needs to "open" or "read" the file from disk — its tools
    are disabled in this deployment and the working directory is sandboxed.
    """
    s = uf.summary or {}
    head = (f"### 文件 `{uf.filename}` (类型={uf.file_type}, "
            f"大小={uf.size_bytes} 字节, sha256={uf.sha256[:12]}…)")
    if uf.file_type == "source":
        content = s.get("content") or s.get("preview") or ""
        truncated = s.get("truncated", False)
        note = " (内容已截断，仅展示前 64KB)" if truncated else ""
        body = f"{note}\n\n```\n{content}\n```"
        return head + body
    if uf.file_type == "binary":
        arch = s.get("arch", "?")
        fmt = s.get("format", "?")
        strings = s.get("strings_sample") or []
        body = (f"\n- 格式: {fmt}, 架构: {arch}\n- strings 抽样: "
                f"{', '.join(strings[:15])}")
        return head + body
    if uf.file_type == "pcap":
        body = f"\n- 抓包格式: {s.get('format', '?')} — {s.get('note', '')}"
        return head + body
    if uf.file_type == "archive":
        manifest = s.get("manifest") or []
        names = "\n".join(f"  - {m['name']} ({m['size']} 字节)"
                          for m in manifest[:30])
        previews = s.get("text_previews") or {}
        body = (f"\n- 条目数: {s.get('entry_count', 0)}\n- 主要文件:\n{names}")
        for name, txt in list(previews.items())[:3]:
            body += f"\n\n#### `{name}`\n```\n{txt[:1500]}\n```"
        return head + body
    if uf.file_type == "document":
        content = s.get("content") or ""
        method = s.get("method", "unknown")
        if content:
            truncated = s.get("truncated", False)
            note = " (内容已截断，仅展示前 64KB)" if truncated else ""
            body = f"\n- 提取方式: {method}{note}\n\n```\n{content}\n```"
        else:
            body = (f"\n- 提取方式: {method}\n- 无法提取文本内容；"
                    "如需 PDF 解析，请在后端安装 `pypdf`")
        return head + body
    if uf.file_type == "other":
        content = s.get("content") or ""
        method = s.get("method", "unknown")
        if content:
            truncated = s.get("truncated", False)
            note = " (内容已截断，仅展示前 64KB)" if truncated else ""
            body = f"\n- 视为文本嵌入{note}\n\n```\n{content}\n```"
            return head + body
        hex_preview = s.get("hex_preview") or ""
        body = f"\n- 二进制文件（前 512 字节十六进制）:\n```\n{hex_preview}\n```"
        return head + body
    return head


def render_uploads_block(uploads: list) -> str:
    """Compose the full uploaded-files section that gets injected into the LLM prompt."""
    if not uploads:
        return ""
    rendered = "\n\n".join(render_for_prompt(u) for u in uploads)
    return (
        "\n\n---\n## 用户上传的文件（内容已完整附在下方，请直接分析，不要尝试访问文件系统）\n\n"
        + rendered
        + "\n\n---\n"
    )
