"""Streaming parser for the MITRE CWE-7 XML release.

The full ``cwec_latest.xml`` is ~18 MB and ~1 000 ``<Weakness>`` entries; we
use ``ET.iterparse`` so peak RSS stays flat regardless of file size and clear
each ``<Weakness>`` element after we have extracted its fields.

Only ``ChildOf`` edges populate ``parents``; ``children`` is derived later in
the storage layer by inverting the parent index (so a single pass suffices).
Peers cover the broader "sibling / sequence" natures listed in CWE schema.

The xhtml mixed content found inside ``<Extended_Description>``,
``<Mitigation><Description>`` and ``<Demonstrative_Example>`` is flattened to
plain text (with ``<xhtml:br/>`` mapped to a newline). For demonstrative
examples we render a small markdown blob so the UI can show the example
narrative + fenced code blocks without any additional sanitization.
"""
from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from .schema import CweEntry

# CWE-7 default namespace + xhtml. Most elements live in the CWE namespace,
# but mixed-content children inside descriptions are xhtml-prefixed.
_CWE_NS = "http://cwe.mitre.org/cwe-7"
_XHTML_NS = "http://www.w3.org/1999/xhtml"

_WS_RE = re.compile(r"[ \t]+")
_NL_RE = re.compile(r"\n{3,}")


def _local(tag: str) -> str:
    """Strip namespace prefix from an ElementTree tag."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def _normalize_ws(text: str) -> str:
    """Collapse runs of spaces/tabs and 3+ newlines, strip outer whitespace."""
    if not text:
        return ""
    text = _WS_RE.sub(" ", text)
    text = _NL_RE.sub("\n\n", text)
    # Trim spaces around individual newlines without collapsing the newline itself.
    text = "\n".join(line.strip() for line in text.split("\n"))
    return text.strip()


def _xhtml_to_text(el: ET.Element) -> str:
    """Flatten mixed xhtml content to plain text. ``<xhtml:br/>`` → ``\\n``;
    ``<xhtml:p>`` / ``<xhtml:div>`` / ``<xhtml:li>`` introduce paragraph breaks.

    Recursive so deeply nested xhtml (e.g. ``<ul><li><div>...</div></li>``) is
    handled correctly.
    """
    parts: list[str] = []
    if el.text:
        parts.append(el.text)
    for child in el:
        tag = _local(child.tag)
        if tag == "br":
            parts.append("\n")
        elif tag in ("p", "div", "li"):
            parts.append("\n")
            parts.append(_xhtml_to_text(child))
            parts.append("\n")
        else:
            parts.append(_xhtml_to_text(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def _text_of(el: ET.Element | None) -> str:
    """Return joined plain text of an element (or '' if missing)."""
    if el is None:
        return ""
    return _normalize_ws(_xhtml_to_text(el))


def _find(el: ET.Element, local_name: str) -> ET.Element | None:
    return el.find(f"{{{_CWE_NS}}}{local_name}")


def _findall(el: ET.Element, local_name: str) -> list[ET.Element]:
    return el.findall(f"{{{_CWE_NS}}}{local_name}")


def _dedup_preserve(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


_PEER_NATURES = {
    "PeerOf",
    "CanPrecede",
    "CanFollow",
    "CanAlsoBe",
    "StartsWith",
    "Requires",
}


def _parse_relationships(weak: ET.Element) -> tuple[list[str], list[str]]:
    parents: list[str] = []
    peers: list[str] = []
    rel = _find(weak, "Related_Weaknesses")
    if rel is None:
        return [], []
    for rw in _findall(rel, "Related_Weakness"):
        nature = rw.get("Nature", "")
        cwe_id = rw.get("CWE_ID")
        if not cwe_id:
            continue
        ref = f"CWE-{cwe_id}"
        if nature == "ChildOf":
            parents.append(ref)
        elif nature in _PEER_NATURES:
            peers.append(ref)
        # MemberOf and others intentionally ignored: they live in view-only
        # entries and would inflate the graph with view nodes.
    return _dedup_preserve(parents), _dedup_preserve(peers)


def _parse_consequences(weak: ET.Element) -> list[dict]:
    out: list[dict] = []
    container = _find(weak, "Common_Consequences")
    if container is None:
        return out
    for cons in _findall(container, "Consequence"):
        scopes = [s.text.strip() for s in _findall(cons, "Scope") if s.text]
        impacts = [i.text.strip() for i in _findall(cons, "Impact") if i.text]
        note_el = _find(cons, "Note")
        out.append(
            {
                "scope": scopes,
                "impact": impacts,
                "note": _text_of(note_el),
            }
        )
    return out


def _parse_mitigations(weak: ET.Element) -> list[dict]:
    out: list[dict] = []
    container = _find(weak, "Potential_Mitigations")
    if container is None:
        return out
    for mit in _findall(container, "Mitigation"):
        phases = [p.text.strip() for p in _findall(mit, "Phase") if p.text]
        strategy_el = _find(mit, "Strategy")
        desc_el = _find(mit, "Description")
        eff_el = _find(mit, "Effectiveness")
        out.append(
            {
                "phase": phases,
                "strategy": (strategy_el.text or "").strip() if strategy_el is not None and strategy_el.text else "",
                "description": _text_of(desc_el),
                "effectiveness": (eff_el.text or "").strip() if eff_el is not None and eff_el.text else "",
            }
        )
    return out


def _parse_detection_methods(weak: ET.Element) -> list[dict]:
    out: list[dict] = []
    container = _find(weak, "Detection_Methods")
    if container is None:
        return out
    for dm in _findall(container, "Detection_Method"):
        method_el = _find(dm, "Method")
        desc_el = _find(dm, "Description")
        eff_el = _find(dm, "Effectiveness")
        out.append(
            {
                "method": (method_el.text or "").strip() if method_el is not None and method_el.text else "",
                "description": _text_of(desc_el),
                "effectiveness": (eff_el.text or "").strip() if eff_el is not None and eff_el.text else "",
            }
        )
    return out


def _render_example_body(ex_el: ET.Element) -> tuple[str, list[str]]:
    """Render a Demonstrative_Example's narrative + code blocks as markdown.

    Strategy: walk children in document order. ``Intro_Text`` is returned
    separately so it lives in its own field. ``Body_Text`` is flattened xhtml
    paragraphs. ``Example_Code`` becomes a fenced code block; the ``Language``
    attribute (e.g. "PHP", "Java") becomes the fence hint. Some legacy entries
    use a sibling ``<Example_Language>`` element instead — handled as fallback.
    """
    parts: list[str] = []
    languages: list[str] = []
    # Look ahead so a standalone Example_Language can be associated with the
    # following Example_Code if Language attr is missing.
    pending_lang: str | None = None
    for child in ex_el:
        tag = _local(child.tag)
        if tag == "Intro_Text":
            continue
        if tag == "Example_Language":
            pending_lang = (child.get("Class") or (child.text or "")).strip() or None
            continue
        if tag == "Example_Code":
            lang = (child.get("Language") or pending_lang or "").strip()
            pending_lang = None
            if lang:
                languages.append(lang)
            nature = (child.get("Nature") or "").strip()
            code = _xhtml_to_text(child).strip("\n")
            # collapse stray runs of >2 blank lines inside the code block,
            # but keep single newlines and indentation intact.
            code = _NL_RE.sub("\n\n", code)
            fence_lang = lang.lower()
            header = f"// {nature}\n" if nature else ""
            parts.append(f"```{fence_lang}\n{header}{code}\n```")
        elif tag in ("Body_Text", "Body"):
            text = _text_of(child)
            if text:
                parts.append(text)
    body_md = "\n\n".join(p for p in parts if p)
    return body_md, _dedup_preserve(languages)


def _parse_demonstrative_examples(weak: ET.Element) -> list[dict]:
    out: list[dict] = []
    container = _find(weak, "Demonstrative_Examples")
    if container is None:
        return out
    for ex in _findall(container, "Demonstrative_Example"):
        intro_el = _find(ex, "Intro_Text")
        body_md, languages = _render_example_body(ex)
        out.append(
            {
                "intro_text": _text_of(intro_el),
                "body_markdown": body_md,
                "languages": languages,
            }
        )
    return out


def _parse_applicable_platforms(weak: ET.Element) -> dict:
    result = {
        "languages": [],
        "oses": [],
        "architectures": [],
        "technologies": [],
    }
    ap = _find(weak, "Applicable_Platforms")
    if ap is None:
        return result
    # Element local name -> result key.
    mapping = {
        "Language": "languages",
        "Operating_System": "oses",
        "Architecture": "architectures",
        "Technology": "technologies",
    }
    for child in ap:
        key = mapping.get(_local(child.tag))
        if not key:
            continue
        # Name takes precedence; fall back to Class for "Not Language-Specific" etc.
        name = (child.get("Name") or child.get("Class") or "").strip()
        prevalence = (child.get("Prevalence") or "").strip()
        if name:
            result[key].append({"name": name, "prevalence": prevalence})
    return result


def _parse_capec_ids(weak: ET.Element) -> list[str]:
    container = _find(weak, "Related_Attack_Patterns")
    if container is None:
        return []
    ids: list[str] = []
    for rap in _findall(container, "Related_Attack_Pattern"):
        cid = rap.get("CAPEC_ID")
        if cid:
            ids.append(str(cid))
    return _dedup_preserve(ids)


def _parse_references(weak: ET.Element) -> list[dict]:
    container = _find(weak, "References")
    if container is None:
        return []
    refs: list[dict] = []
    for r in _findall(container, "Reference"):
        rid = r.get("External_Reference_ID", "")
        if not rid:
            continue
        refs.append({"id": rid, "section": r.get("Section", "") or ""})
    return refs


def _parse_weakness(weak: ET.Element) -> CweEntry:
    parents, peers = _parse_relationships(weak)
    desc_el = _find(weak, "Description")
    ext_desc_el = _find(weak, "Extended_Description")
    likelihood_el = _find(weak, "Likelihood_Of_Exploit")
    likelihood = None
    if likelihood_el is not None and likelihood_el.text:
        likelihood = likelihood_el.text.strip() or None
    return CweEntry(
        id=f"CWE-{weak.get('ID')}",
        name=weak.get("Name", "") or "",
        abstraction=weak.get("Abstraction", "") or "",
        structure=weak.get("Structure", "Simple") or "Simple",
        status=weak.get("Status", "Incomplete") or "Incomplete",
        description=_text_of(desc_el),
        extended_description=_text_of(ext_desc_el),
        likelihood=likelihood,
        parents=parents,
        peers=peers,
        consequences=_parse_consequences(weak),
        mitigations=_parse_mitigations(weak),
        detection_methods=_parse_detection_methods(weak),
        demonstrative_examples=_parse_demonstrative_examples(weak),
        applicable_platforms=_parse_applicable_platforms(weak),
        capec_ids=_parse_capec_ids(weak),
        references=_parse_references(weak),
    )


def parse_cwec_xml(path: Path | str) -> list[CweEntry]:
    """Stream-parse a MITRE CWE XML release file.

    Returns a list of ``CweEntry`` objects in source order. ``children`` is
    intentionally left empty here; the storage layer fills it once all
    entries are visible via a reverse pass over ``parents``.

    Memory is kept flat by calling ``el.clear()`` after each ``<Weakness>`` is
    consumed, so the 18 MB full release file parses in O(entry size) RSS
    rather than O(file size).
    """
    weak_tag = f"{{{_CWE_NS}}}Weakness"
    entries: list[CweEntry] = []
    ctx = ET.iterparse(str(path), events=("end",))
    for _event, el in ctx:
        if el.tag == weak_tag:
            entries.append(_parse_weakness(el))
            el.clear()
    return entries
