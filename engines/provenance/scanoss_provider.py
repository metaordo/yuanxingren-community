"""ScanOSS 实现:WFP 指纹 → osskb /scan/direct → 标准化 match。唯一出网点。

注意:此模块名含 scanoss 仅为内部实现细节,对外一律匿名化为「玄刃开源比对引擎」。
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from scanoss.scanossapi import ScanossApi

from .fingerprint import build_project_wfp
from .models import ProvenanceMatch
from .provider import ProvenanceProvider, ProvenanceError, ProgressCb

logger = logging.getLogger("pentest-agent.provenance")

# osskb /scan/direct 单次 POST 上限约 64KB。按 文件数 + 字节数 双上限分批:
# 字节数留在 64KB 安全线内,文件数放宽(真实代码单文件指纹通常很小),
# 让小文件密集打包以减少请求数 → 降低触发免费版 503 限流的概率。
_CHUNK_MAX_FILES = int(os.environ.get("PA_PROVENANCE_CHUNK_FILES", "200"))
_CHUNK_MAX_BYTES = int(os.environ.get("PA_PROVENANCE_CHUNK_BYTES", str(60 * 1024)))
# 每批请求间隔(秒),节流以避免免费版限流;大项目会更慢但更稳。
_CHUNK_DELAY_S = float(os.environ.get("PA_PROVENANCE_CHUNK_DELAY", "0.3"))
# 单批请求重试次数(传给 scanoss 客户端)。调低以便限流时快速失败 → 走优雅降级,
# 不在每个 503 批上耗 5×5s。
_CHUNK_RETRY = int(os.environ.get("PA_PROVENANCE_RETRY", "2"))
# 最低可信覆盖率:已成功比对的有效行 / 全部有效行。低于此值说明大部分文件因限流未检查,
# 此时给确定性结论会误导(如"100% 高度复用"实际只看了 0.5% 文件)→ 诚实失败。
_MIN_COVERAGE = float(os.environ.get("PA_PROVENANCE_MIN_COVERAGE", "0.6"))
# 连续失败这么多批后早停:免费版触发限流后基本会持续 503,继续打也是失败,提前结束省时间。
_MAX_CONSEC_FAIL = int(os.environ.get("PA_PROVENANCE_MAX_CONSEC_FAIL", "25"))


def _chunk_files(chunk: str) -> list[str]:
    """从一段 WFP 解析出它覆盖的文件相对路径(file=<md5>,<size>,<name>)。"""
    out: list[str] = []
    for line in chunk.split("\n"):
        if line.startswith("file="):
            parts = line[len("file="):].split(",", 2)
            if len(parts) == 3:
                out.append(parts[2])
    return out


def _split_wfp_files(wfp: str) -> list[str]:
    """把合并 WFP 拆成按文件的块(每块以 `file=` 行开头)。"""
    blocks: list[str] = []
    cur: list[str] = []
    for line in wfp.split("\n"):
        if line.startswith("file=") and cur:
            blocks.append("\n".join(cur))
            cur = [line]
        else:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))
    return [b for b in blocks if b.strip()]


def _chunk_wfp(wfp: str) -> list[str]:
    """按 文件数 + 字节数 双上限把 WFP 分批,每批是一段可独立提交的 WFP。"""
    chunks: list[str] = []
    cur: list[str] = []
    cur_bytes = 0
    for blk in _split_wfp_files(wfp):
        bsize = len(blk.encode("utf-8")) + 1
        if cur and (len(cur) >= _CHUNK_MAX_FILES or cur_bytes + bsize > _CHUNK_MAX_BYTES):
            chunks.append("\n".join(cur))
            cur, cur_bytes = [], 0
        cur.append(blk)
        cur_bytes += bsize
    if cur:
        chunks.append("\n".join(cur))
    return chunks


def _line_count(lines: str) -> int:
    """'40-92' → 53(含端点);'7' → 1;空/异常 → 0。"""
    if not lines:
        return 0
    try:
        if "-" in lines:
            a, b = lines.split("-", 1)
            return max(0, int(b) - int(a) + 1)
        int(lines)  # Validate single line is a number
        return 1
    except (ValueError, TypeError):
        return 0


def _parse_scan_result(raw: dict, line_map: dict[str, int] | None = None) -> list[ProvenanceMatch]:
    """扫描结果 dict(以你的文件为键)→ ProvenanceMatch 列表。

    line_map: 每文件有效行数 map,用于 file 类型匹配(整文件命中开源)时
    计算 matched_lines。snippet 类型仍走 _line_count(lines_str) 逻辑。
    """
    _lmap = line_map or {}
    out: list[ProvenanceMatch] = []
    for your_file, hits in (raw or {}).items():
        if not isinstance(hits, list):
            continue
        for h in hits:
            if not isinstance(h, dict):
                continue
            mtype = h.get("id", "none")
            if mtype not in ("file", "snippet"):
                continue  # "none" = 无匹配
            lines_str = h.get("lines", "")
            if mtype == "file":
                matched_lines = _lmap.get(your_file, 0)
            else:
                matched_lines = _line_count(lines_str)
            try:
                sim = int(str(h.get("matched", "0")).rstrip("%") or "0")
            except ValueError:
                sim = 100 if mtype == "file" else 0
            lic = ""
            licenses = h.get("licenses") or []
            if licenses and isinstance(licenses[0], dict):
                lic = licenses[0].get("name", "")
            out.append(ProvenanceMatch(
                your_file=your_file,
                lines=lines_str or "all",
                match_type=mtype,
                matched_lines=matched_lines,
                source_project=h.get("component", "") or h.get("vendor", ""),
                source_version=h.get("version", "") or "",
                source_file=h.get("file", "") or "",
                similarity=sim if sim else (100 if mtype == "file" else 0),
                license=lic,
            ))
    return out


class ScanossProvider(ProvenanceProvider):
    def __init__(self, *, timeout: int = 120) -> None:
        # url=None → 默认 api.osskb.org;api_key=None → 免 key
        self._url: str | None = os.environ.get("PA_PROVENANCE_URL") or None
        self._timeout = timeout

    def scan_project(
        self, project_root: Path, progress_cb: "ProgressCb | None" = None,
    ) -> tuple[list[ProvenanceMatch], int, list[str]]:
        def _report(stage: str, pct: int) -> None:
            if progress_cb:
                progress_cb(stage, pct)

        # 指纹阶段占 15-60%:把每文件进度映射进这个区间。
        def _fp_cb(done: int, total: int) -> None:
            pct = 15 + int(45 * done / total) if total else 60
            _report(f"生成代码指纹 {done}/{total} 文件", pct)

        _report("准备指纹", 12)
        wfp, effective_lines, skipped, line_map = build_project_wfp(project_root, _fp_cb)
        if not wfp:
            return [], effective_lines, skipped
        chunks = _chunk_wfp(wfp)
        api = ScanossApi(url=self._url, api_key=None, timeout=self._timeout,
                         retry=_CHUNK_RETRY)
        raw_all: dict = {}
        unchecked: list[str] = []  # 因限流/错误未能比对的文件,优雅降级而非整单失败
        consec_fail = 0
        for i, chunk in enumerate(chunks):
            # 比对阶段占 65-90%:按批次推进,大项目也能看到进度。
            pct = 65 + int(25 * i / len(chunks)) if chunks else 65
            _report(f"上传指纹并比对开源库 ({i + 1}/{len(chunks)})", pct)
            try:
                raw = api.scan(chunk)
                if raw:
                    raw_all.update(raw)
                consec_fail = 0
            except Exception as exc:
                logger.warning("provenance scan chunk %d/%d failed: %s",
                               i + 1, len(chunks), exc)
                unchecked.extend(_chunk_files(chunk))
                consec_fail += 1
                if consec_fail >= _MAX_CONSEC_FAIL:
                    # 持续限流,剩余批大概率也失败 → 早停,剩余文件全标未检查。
                    for rc in chunks[i + 1:]:
                        unchecked.extend(_chunk_files(rc))
                    logger.warning("provenance aborting after %d consecutive failures, "
                                   "%d chunks skipped", consec_fail, len(chunks) - i - 1)
                    break
            if _CHUNK_DELAY_S and i < len(chunks) - 1:
                time.sleep(_CHUNK_DELAY_S)

        # 覆盖率门:已比对的有效行占比。太低则结论不可信(免费引擎限流把大部分文件挡掉),
        # 诚实失败而非给出一个看似自信的错误结论。
        unchecked_lines = sum(line_map.get(f, 0) for f in unchecked)
        checked_lines = max(0, effective_lines - unchecked_lines)
        coverage = (checked_lines / effective_lines) if effective_lines else 1.0
        if coverage < _MIN_COVERAGE:
            logger.warning("provenance coverage too low %.1f%%: %d/%d files unchecked",
                           coverage * 100, len(unchecked), len(line_map))
            raise ProvenanceError(
                f"比对覆盖不足(仅 {coverage * 100:.0f}%):项目过大触发免费比对引擎限流。"
                f"请减小项目规模后重试,或改用自托管比对引擎")

        # 部分失败但覆盖足够 → 优雅降级:未检查文件的行从分母剔除,比例只覆盖已检查部分。
        if unchecked:
            effective_lines = checked_lines
            skipped = skipped + unchecked
            logger.warning("provenance partial coverage %.0f%%: %d files unchecked (rate-limited)",
                           coverage * 100, len(unchecked))

        _report("汇总溯源结果", 92)
        matches = _parse_scan_result(raw_all, line_map)
        return matches, effective_lines, skipped
