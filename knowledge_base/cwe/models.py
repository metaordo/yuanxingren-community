"""SQLModel persistence for CWE entries.

The entire detail payload (consequences/mitigations/examples/etc.) is stored
as a single JSON blob to keep the schema flat — BM25 doesn't need these fields
indexed, and the detail view fetches by id and deserializes once.

Indexed fields (abstraction, status) are filtered server-side in /api/cwe/list
and /api/cwe/search.
"""
from __future__ import annotations
from sqlmodel import SQLModel, Field, Column, JSON


class CweEntryRow(SQLModel, table=True):
    __tablename__ = "cwe_entries"

    id: str = Field(primary_key=True, max_length=16)        # "CWE-79"
    name: str = Field(max_length=512)
    abstraction: str = Field(index=True, max_length=16)     # Pillar/Class/Base/Variant/Compound
    structure: str = Field(default="Simple", max_length=16)
    status: str = Field(index=True, max_length=16)
    description: str = ""                                   # short
    extended_description: str = ""                          # long, plain
    likelihood: str | None = Field(default=None, max_length=16)
    # Graph edges as JSON list[str].
    parents: list = Field(default_factory=list, sa_column=Column(JSON))
    children: list = Field(default_factory=list, sa_column=Column(JSON))
    peers: list = Field(default_factory=list, sa_column=Column(JSON))
    # Rich detail blob: consequences / mitigations / detection_methods /
    # demonstrative_examples / applicable_platforms / capec_ids / references.
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
