"""In-memory CWE node. Mirrors the MITRE CWE-7 XML schema, lightly normalized.

The dataclass is the business object the parser produces and the retriever
indexes; persistence happens via knowledge_base/cwe/models.py:CweEntryRow.

Field naming follows MITRE: abstraction = Pillar/Class/Base/Variant/Compound,
status = Stable/Draft/Incomplete/Deprecated. Graph edges (parents/children/peers)
are CWE id strings like "CWE-79".
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class CweEntry:
    id: str                         # "CWE-79"
    name: str
    abstraction: str                # Pillar / Class / Base / Variant / Compound
    structure: str = "Simple"       # Simple / Composite / Chain
    status: str = "Incomplete"      # Stable / Draft / Incomplete / Deprecated / Obsolete
    description: str = ""           # short
    extended_description: str = ""  # long, HTML stripped to plain text
    likelihood: str | None = None   # High / Medium / Low / Unknown
    # Graph edges (only ChildOf relationships from View 1000 / 699 / 1003 are kept).
    # Children are derived in storage.bulk_insert() by inverting parents.
    parents: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    peers: list[str] = field(default_factory=list)        # PeerOf / CanAlsoBe / CanPrecede
    # Rich detail fields used by the detail view, not by BM25.
    consequences: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    detection_methods: list[dict] = field(default_factory=list)
    demonstrative_examples: list[dict] = field(default_factory=list)
    applicable_platforms: dict = field(default_factory=dict)  # {languages, oses, architectures, technologies}
    capec_ids: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
