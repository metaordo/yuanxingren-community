"""溯源结果数据类(纯数据,无 IO)。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProvenanceMatch:
    """单条溯源匹配:你的某文件命中某开源项目。"""
    your_file: str            # 项目内相对路径
    lines: str                # "40-92" 或 "all"(整文件)
    match_type: str           # "file" | "snippet"
    matched_lines: int        # 该 match 计入复用的行数
    source_project: str       # 来源开源项目名(展示给用户)
    source_version: str       # 版本,缺失为 ""
    source_file: str          # 来源文件路径,缺失为 ""
    similarity: int           # 单段相似度 0-100(file 类型为 100)
    license: str = ""         # 许可证 SPDX id,缺失为 ""


@dataclass
class ComplianceReport:
    """整项目量化报告。"""
    reuse_ratio: float                       # 0.0-1.0
    self_ratio: float                        # 1 - reuse_ratio
    verdict: str                             # 五档之一
    total_effective_lines: int
    reused_lines: int
    by_project: list[dict] = field(default_factory=list)
    # [{"project":str,"version":str,"ratio":float,"file_count":int}]
    matches: list[ProvenanceMatch] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
