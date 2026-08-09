"""源码树 → WFP 指纹。纯本地,无网络。封装 scanoss-py 的 Winnowing。"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from scanoss.winnowing import Winnowing

from .aggregator import is_generated_file

# 跳过的二进制/超大文件:扩展名 + 单文件上限
_BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar",
                ".gz", ".o", ".a", ".so", ".bin", ".exe", ".dll", ".class",
                ".jar", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".mp3"}
_MAX_FILE_BYTES = 1_000_000  # 单文件 1MB 上限


def count_effective_lines(text: str) -> int:
    """有效代码行:剥离空行与纯注释行(// # 开头)。简易启发式。"""
    n = 0
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith(("//", "#", "*", "/*")):
            continue
        n += 1
    return n


def generate_wfp(disk_path: str, rel_name: str) -> str:
    """对单文件生成 WFP。disk_path=磁盘全路径,rel_name=记录进 WFP 的相对名。"""
    return Winnowing().wfp_for_file(disk_path, rel_name)


def _should_skip(path: Path, rel: str) -> bool:
    if is_generated_file(rel):
        return True
    if path.suffix.lower() in _BINARY_EXTS:
        return True
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return True
    except OSError:
        return True
    return False


def build_project_wfp(
    project_root: Path,
    progress_cb: Callable[[int, int], None] | None = None,
) -> tuple[str, int, list[str], dict[str, int]]:
    """遍历项目树 → 拼接全部文件 WFP + 统计有效行 + 跳过清单 + 每文件有效行数 map。

    Returns (combined_wfp, total_effective_lines, skipped_rel_paths, line_map)
    其中 line_map: dict[rel_path, effective_lines],键与 ScanOSS 返回 dict 的键一致。
    progress_cb(done, total) 在指纹过程中被节流调用(最多 ~20 次),用于上报进度。
    """
    win = Winnowing(size_limit=True)  # 单文件指纹封顶,避免超大文件撑爆单次 POST
    parts: list[str] = []
    total_effective = 0
    skipped: list[str] = []
    line_map: dict[str, int] = {}
    files = [p for p in sorted(project_root.rglob("*")) if p.is_file()]
    total = len(files)
    # 节流:最多上报 ~20 次,避免大项目上千次回调(每次回调可能写 DB)。
    step = max(1, total // 20)
    for idx, p in enumerate(files):
        rel = str(p.relative_to(project_root))
        if _should_skip(p, rel):
            skipped.append(rel)
        else:
            try:
                raw = p.read_bytes()
                text = raw.decode("utf-8", errors="ignore")
                eff = count_effective_lines(text)
                total_effective += eff
                line_map[rel] = eff
                wfp = win.wfp_for_contents(rel, False, raw)
                if wfp:
                    parts.append(wfp)
            except OSError:
                skipped.append(rel)
        if progress_cb and (idx % step == 0 or idx == total - 1):
            progress_cb(idx + 1, total)
    return "".join(parts), total_effective, skipped, line_map
