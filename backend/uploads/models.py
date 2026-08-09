"""Uploaded file persistence model."""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class UploadedFile(SQLModel, table=True):
    """User-uploaded file (source code, binary, pcap, archive)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str = Field(max_length=512)
    content_type: str = Field(max_length=128)  # MIME type
    size_bytes: int
    sha256: str = Field(max_length=64, index=True)
    storage_path: str = Field(max_length=1024)  # relative to PA_DATA_DIR
    file_type: str = Field(max_length=32)  # source|binary|pcap|archive|other
    summary: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # summary examples:
    #   source: {"file_tree": [...], "key_snippets": [...]}
    #   binary: {"arch": "x86_64", "format": "ELF", "strings_sample": [...]}
    #   archive: {"manifest": [...], "text_previews": {...}}
    owner_id: int = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
