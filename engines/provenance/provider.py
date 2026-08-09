"""可插拔溯源 provider 抽象。新增服务只需实现 scan_project。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable

from .models import ProvenanceMatch

# 进度回调:(stage 文案, 0-100 百分比)。provider 在各阶段调用上报。
ProgressCb = Callable[[str, int], None]


class ProvenanceError(Exception):
    """溯源过程不可恢复错误(出网失败/解析失败)。调用方据此标 failed。"""


class ProvenanceProvider(ABC):
    """对外统一接口。实现内部用什么服务对用户不可见。"""

    @abstractmethod
    def scan_project(
        self, project_root: Path, progress_cb: ProgressCb | None = None,
    ) -> tuple[list[ProvenanceMatch], int, list[str]]:
        """返回 (matches, total_effective_lines, skipped)。失败抛 ProvenanceError。

        progress_cb(stage, pct) 可选,用于上报中间进度。
        """
        raise NotImplementedError
