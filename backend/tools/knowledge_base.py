"""Knowledge base Tool plugin: exposes KB search to the LLM orchestrator."""
from __future__ import annotations
from pentest_agent_sdk.contracts import HealthStatus
from ...knowledge_base import retriever


class KnowledgeBaseTool:
    name = "knowledge_base"
    version = "0.1.0"
    description = (
        "Search the TCP/IP protocol stack security knowledge base (403 entries "
        "covering RFCs, papers, CVEs, reports) by keyword and metadata filters."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "free-text query"},
            "category": {"type": "string",
                         "description": "optional category filter (TCP, DNS, BGP, TLS, ...)"},
            "entry_type": {"type": "string",
                           "description": "optional type filter (RFC, Paper, CVE, ...)"},
            "top_k": {"type": "integer", "default": 10}
        },
        "required": ["query"]
    }

    def invoke(self, args: dict) -> dict:
        query = args["query"]
        category = args.get("category")
        entry_type = args.get("entry_type")
        top_k = int(args.get("top_k", 10))
        results = retriever.search(query, category=category,
                                    entry_type=entry_type, top_k=top_k)
        return {
            "query": query,
            "count": len(results),
            "hits": [{
                "id": r.id,
                "title": r.title,
                "type": r.type.value,
                "category": r.category,
                "year": r.year,
                "summary": r.summary[:300],
                "url": r.url,
            } for r in results]
        }

    def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True, version=self.version)
