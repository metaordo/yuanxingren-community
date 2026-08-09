"""Upload API: multipart file upload, list, detail, delete."""
from __future__ import annotations
import hashlib
import logging
import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlmodel import Session, select

from ..auth.middleware import get_current_user
from ..auth.models import User
from ..db import get_session
from .models import UploadedFile
from .preprocess import classify, summarize

router = APIRouter(prefix="/api/uploads", tags=["uploads"])
log = logging.getLogger(__name__)

_DATA_DIR = Path(os.environ.get("PA_DATA_DIR", "./data"))
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_FILES_PER_REQUEST = 5


def _upload_dir(user_id: int, upload_id: int) -> Path:
    return _DATA_DIR / "uploads" / str(user_id) / str(upload_id)


@router.post("")
async def upload_files(
    files: list[UploadFile] = File(...),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    if len(files) > MAX_FILES_PER_REQUEST:
        raise HTTPException(status_code=400,
                            detail=f"最多同时上传 {MAX_FILES_PER_REQUEST} 个文件")

    results = []
    for f in files:
        content = await f.read()
        size = len(content)
        if size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"文件 {f.filename} 超过 200MB 限制 ({size} bytes)")
        if size == 0:
            raise HTTPException(status_code=400,
                                detail=f"文件 {f.filename} 为空")

        sha = hashlib.sha256(content).hexdigest()
        file_type = classify(f.filename or "unknown", content[:4096])

        # Persist model first to get ID
        uf = UploadedFile(
            filename=f.filename or "unknown",
            content_type=f.content_type or "application/octet-stream",
            size_bytes=size,
            sha256=sha,
            storage_path="",  # filled below
            file_type=file_type,
            summary={},
            owner_id=user.id,
        )
        session.add(uf)
        session.commit()
        session.refresh(uf)

        # Write to disk — resolve the final path FIRST to prevent
        # path-traversal via crafted filenames (e.g. "../../etc/cron.d/x").
        dest_dir = _upload_dir(user.id, uf.id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(f.filename or "upload").name  # strip directory components
        if safe_name in ("", ".", ".."):
            raise HTTPException(status_code=400, detail=f"invalid filename: {f.filename}")
        dest_file = (dest_dir / safe_name).resolve()
        # Enforce that the resolved path stays inside dest_dir.
        if not str(dest_file).startswith(str(dest_dir.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="path traversal denied")
        dest_file.write_bytes(content)

        rel_path = str(dest_file.relative_to(_DATA_DIR))
        uf.storage_path = rel_path

        # Generate summary
        try:
            uf.summary = summarize(dest_file, uf.filename, size, file_type)
        except Exception as e:
            log.warning("preprocess failed for %s: %s", uf.filename, e)
            uf.summary = {"error": str(e)}

        session.add(uf)
        session.commit()
        session.refresh(uf)

        results.append({
            "id": uf.id,
            "filename": uf.filename,
            "file_type": uf.file_type,
            "size_bytes": uf.size_bytes,
            "sha256": uf.sha256,
            "summary": uf.summary,
        })

    return {"uploads": results}


@router.get("")
def list_uploads(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    rows = session.exec(
        select(UploadedFile)
        .where(UploadedFile.owner_id == user.id)
        .order_by(UploadedFile.created_at.desc())  # type: ignore[union-attr]
    ).all()
    return [{
        "id": r.id,
        "filename": r.filename,
        "file_type": r.file_type,
        "size_bytes": r.size_bytes,
        "sha256": r.sha256,
        "summary": r.summary,
        "created_at": r.created_at.isoformat(),
    } for r in rows]


@router.get("/{upload_id}")
def get_upload(
    upload_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    uf = session.get(UploadedFile, upload_id)
    if not uf or uf.owner_id != user.id:
        raise HTTPException(status_code=404, detail="not found")
    return {
        "id": uf.id,
        "filename": uf.filename,
        "file_type": uf.file_type,
        "size_bytes": uf.size_bytes,
        "sha256": uf.sha256,
        "content_type": uf.content_type,
        "summary": uf.summary,
        "created_at": uf.created_at.isoformat(),
    }


@router.delete("/{upload_id}")
def delete_upload(
    upload_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    uf = session.get(UploadedFile, upload_id)
    if not uf or uf.owner_id != user.id:
        raise HTTPException(status_code=404, detail="not found")
    # Remove file from disk
    try:
        full_path = _DATA_DIR / uf.storage_path
        if full_path.exists():
            full_path.unlink()
        parent = full_path.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
    except Exception as e:
        log.warning("file cleanup failed for upload %d: %s", upload_id, e)
    session.delete(uf)
    session.commit()
    return {"ok": True}
