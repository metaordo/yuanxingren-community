"""Parse NVD CVE JSON feed entries into our canonical format."""
from __future__ import annotations


def parse_cve_item(item: dict) -> dict:
    """Parse one CVE item from NVD JSON feed into a flat dict.

    Extracts: cve_id, description (en), description_zh (if available),
    cvss_score, severity, vector_string, affected_products, affected_versions.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Descriptions
    desc_en = ""
    desc_zh = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en" and not desc_en:
            desc_en = d.get("value", "")
        elif d.get("lang") == "zh" and not desc_zh:
            desc_zh = d.get("value", "")

    # CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
    score = 0.0
    severity = "UNKNOWN"
    vector = ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = float(cvss.get("baseScore", 0))
            severity = cvss.get("baseSeverity", "UNKNOWN")
            vector = cvss.get("vectorString", "")
            break

    # Affected products (CPE-based extraction)
    products = _extract_products(cve.get("configurations", []))
    versions = _extract_versions(cve.get("configurations", []))

    return {
        "cve_id": cve_id,
        "description": desc_en,
        "description_zh": desc_zh,
        "cvss_score": score,
        "severity": severity,
        "vector_string": vector,
        "affected_products": products,
        "affected_versions": versions,
        "published": cve.get("published", ""),
        "updated": item.get("lastModifiedDate", ""),
    }


def _extract_products(configurations: list) -> str:
    """Extract product names from CPE URIs in configurations."""
    prods: set[str] = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    prods.add(parts[4].lower())
    return ",".join(sorted(prods))


def _extract_versions(configurations: list) -> str:
    """Extract version ranges from CPE match criteria."""
    versions: set[str] = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 6:
                    ver = parts[5]
                    if ver and ver != "*":
                        versions.add(ver)
                for ver_field in ("versionStartIncluding", "versionStartExcluding",
                                  "versionEndIncluding", "versionEndExcluding"):
                    v = match.get(ver_field)
                    if v:
                        versions.add(v)
    return ",".join(sorted(versions))
