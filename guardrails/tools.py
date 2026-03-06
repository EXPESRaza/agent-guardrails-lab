from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ToolResult:
    ok: bool
    output: str
    meta: Dict[str, Any]


class Tools:
    def search_web(self, query: str) -> ToolResult:
        return ToolResult(True, f"[search_web] Results for: {query}", {"tool": "search_web"})

    def send_email(self, to: str, subject: str, body: str) -> ToolResult:
        return ToolResult(True, f"[send_email] Email queued to {to} with subject '{subject}'.", {"tool": "send_email"})

    def delete_records(self, table: str, where: str) -> ToolResult:
        return ToolResult(True, f"[delete_records] Deleted from {table} where {where}.", {"tool": "delete_records"})

    def customer_lookup(self, query: str) -> ToolResult:
        return ToolResult(True, f"[customer_lookup] Customer found for query: {query}", {"tool": "customer_lookup"})