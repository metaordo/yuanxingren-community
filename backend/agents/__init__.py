"""Multi-agent workflow runtime: orchestrates N specialized LLM agents over
a source-code project, with a Supervisor that dynamically picks workers and
a Verifier that cross-validates findings before the Reporter aggregates.

Public surface (M2):
  - run_multi_agent(prompt, target, upload, user_id) -> dict          (sync)
  - astream_multi_agent(prompt, target, upload, user_id) -> async iterator
"""
