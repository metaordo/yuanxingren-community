"""PDF report rendering: markdown → HTML → weasyprint → application/pdf.

Used by the AgentWorkflow side-panel download button across all chat modes
(engine / direct / multi_agent). Body markdown comes from the client; we
own the styling (brand palette, CJK fonts, syntax highlighting) so reports
are visually consistent regardless of which LLM produced the text.
"""
from __future__ import annotations
import io
import logging
from datetime import datetime

import markdown
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from pygments.formatters import HtmlFormatter
from weasyprint import HTML

from ..auth.middleware import get_current_user
from ..auth.models import User

router = APIRouter(prefix="/api/reports", tags=["reports"])
log = logging.getLogger(__name__)

MAX_MARKDOWN_BYTES = 2_000_000  # 2 MB; multi-agent reports are usually <50 KB


class RenderPdfIn(BaseModel):
    content: str = Field(..., min_length=1)
    mode: str = Field("multi_agent", max_length=32)
    target_label: str | None = Field(None, max_length=256)


# Pygments code-highlight CSS — generated once at import time.
_PYGMENTS_CSS = HtmlFormatter(style="friendly").get_style_defs(".codehilite")


def _build_css() -> str:
    """Brand-styled print CSS. Inlined into <style> so the PDF is self-contained.

    Uses Noto Sans CJK SC (installed system-wide via fonts-noto-cjk) for body
    text and DejaVu Sans Mono for code; both are present on the VPS.
    """
    return f"""
    @page {{
      size: A4;
      margin: 18mm 16mm 22mm 16mm;
      @bottom-right {{
        content: counter(page) " / " counter(pages);
        font-family: "Noto Sans CJK SC", sans-serif;
        font-size: 9pt;
        color: #888;
      }}
      @bottom-left {{
        content: "Pentest Agent · 渗透测试分析报告";
        font-family: "Noto Sans CJK SC", sans-serif;
        font-size: 9pt;
        color: #888;
      }}
    }}
    html, body {{
      font-family: "Noto Sans CJK SC", "PingFang SC", "Microsoft YaHei",
                    "Helvetica Neue", Arial, sans-serif;
      font-size: 10.5pt;
      line-height: 1.65;
      color: #1f1f1f;
    }}
    .pa-cover {{
      border-bottom: 3px solid #e53834;
      padding-bottom: 14px;
      margin-bottom: 24px;
    }}
    .pa-cover h1 {{
      margin: 0;
      font-size: 22pt;
      color: #1f1f1f;
      letter-spacing: 0.5px;
    }}
    .pa-cover .pa-sub {{
      margin-top: 6px;
      font-size: 10pt;
      color: #666;
    }}
    .pa-cover .pa-sub strong {{
      color: #e53834;
      font-weight: 600;
    }}
    h1, h2, h3, h4 {{
      color: #1f1f1f;
      font-weight: 600;
      page-break-after: avoid;
    }}
    h1 {{ font-size: 17pt; margin-top: 22px; margin-bottom: 10px;
          border-bottom: 1px solid #eee; padding-bottom: 4px; }}
    h2 {{ font-size: 14pt; margin-top: 18px; margin-bottom: 8px; color: #c5302e; }}
    h3 {{ font-size: 12pt; margin-top: 14px; margin-bottom: 6px; }}
    h4 {{ font-size: 11pt; margin-top: 10px; margin-bottom: 4px; color: #555; }}
    p {{ margin: 0.5em 0; }}
    ul, ol {{ margin: 0.4em 0 0.4em 1.2em; padding-left: 0.5em; }}
    li {{ margin: 0.15em 0; }}
    strong {{ color: #1f1f1f; }}
    em {{ color: #555; }}
    code {{
      font-family: "JetBrains Mono", "Fira Code", "Source Code Pro",
                    "DejaVu Sans Mono", "Noto Sans Mono CJK SC", monospace;
      background: #f4f4f5;
      border: 1px solid #e4e4e7;
      border-radius: 3px;
      padding: 1px 4px;
      font-size: 9.5pt;
      color: #c5302e;
    }}
    pre {{
      font-family: "JetBrains Mono", "Fira Code", "Source Code Pro",
                    "DejaVu Sans Mono", monospace;
      background: #fafafa;
      border: 1px solid #e4e4e7;
      border-left: 3px solid #e53834;
      border-radius: 4px;
      padding: 10px 12px;
      font-size: 9pt;
      line-height: 1.5;
      overflow-x: auto;
      page-break-inside: avoid;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    pre code {{
      background: transparent;
      border: none;
      padding: 0;
      color: inherit;
      font-size: inherit;
    }}
    .codehilite {{ margin: 8px 0; }}
    table {{
      border-collapse: collapse;
      margin: 10px 0;
      width: 100%;
      page-break-inside: avoid;
    }}
    th, td {{
      border: 1px solid #d4d4d8;
      padding: 5px 8px;
      text-align: left;
      vertical-align: top;
      font-size: 9.5pt;
    }}
    th {{
      background: #fff5f4;
      color: #c5302e;
      font-weight: 600;
    }}
    blockquote {{
      border-left: 3px solid #e53834;
      padding: 4px 12px;
      margin: 10px 0;
      background: #fff7f6;
      color: #555;
    }}
    a {{ color: #c5302e; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    hr {{ border: none; border-top: 1px solid #e4e4e7; margin: 18px 0; }}

    {_PYGMENTS_CSS}
    """


_MODE_LABEL = {
    "engine": "深度引擎模式",
    "direct": "LLM 直审模式",
    "multi_agent": "多 Agent 并行模式",
    "x_scan": "X-Scan 主动扫描",
    "compliance": "开源合规溯源",
}


def _wrap_html(md_html: str, mode: str, target_label: str | None) -> str:
    """Wrap rendered markdown body in a brand-styled HTML document."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    mode_label = _MODE_LABEL.get(mode, mode)
    target_line = f"<span class='pa-sub-label'>分析目标</span> {target_label}" \
                  if target_label else "<span class='pa-sub-label'>分析目标</span> —"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Pentest Agent — 渗透测试分析报告</title>
<style>{_build_css()}</style>
</head>
<body>
<div class="pa-cover">
  <h1>渗透测试分析报告</h1>
  <div class="pa-sub">
    <strong>{mode_label}</strong> · 生成时间 {now_str} · {target_line}
  </div>
</div>
{md_html}
</body>
</html>"""


@router.post("/render-pdf")
def render_pdf(data: RenderPdfIn,
                _user: User = Depends(get_current_user)) -> Response:
    """Render markdown to a styled PDF and stream it back to the browser."""
    body = data.content
    if len(body.encode("utf-8")) > MAX_MARKDOWN_BYTES:
        raise HTTPException(status_code=413,
                             detail="report too large (max 2 MB markdown)")
    try:
        md_html = markdown.markdown(
            body,
            extensions=["fenced_code", "tables", "codehilite", "sane_lists",
                         "toc", "nl2br"],
            extension_configs={
                "codehilite": {"css_class": "codehilite", "guess_lang": False},
            },
        )
    except Exception as e:  # noqa: BLE001
        log.warning("markdown rendering failed: %s", e)
        raise HTTPException(status_code=400, detail=f"markdown error: {e}")

    full_html = _wrap_html(md_html, data.mode, data.target_label)
    try:
        buf = io.BytesIO()
        HTML(string=full_html).write_pdf(target=buf)
        pdf_bytes = buf.getvalue()
    except Exception as e:  # noqa: BLE001
        log.exception("weasyprint render failed")
        raise HTTPException(status_code=500, detail=f"pdf render error: {e}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    target_slug = ""
    if data.target_label:
        # Sanitize: keep filename safe but informative
        safe = "".join(c if c.isalnum() or c in "-_." else "-"
                        for c in data.target_label)[:40]
        target_slug = f"-{safe}"
    filename = f"pentest-report-{stamp}-{data.mode}{target_slug}.pdf"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Length": str(len(pdf_bytes)),
    }
    return Response(content=pdf_bytes, media_type="application/pdf",
                     headers=headers)
