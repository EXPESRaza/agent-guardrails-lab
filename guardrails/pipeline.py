from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

from guardrails.audit import AuditRecord
from guardrails.deterministic import DeterministicPolicy
from guardrails.injection import PromptInjectionPolicy
from guardrails.model_based import ModelBasedPolicy
from guardrails.pii import PIIMiddleware
from guardrails.policy import PolicyConfig
from guardrails.risk import RiskScore
from guardrails.tools import ToolResult, Tools


@dataclass
class TraceEvent:
    stage: str
    decision: str
    details: str
    payload: Dict[str, Any] = field(default_factory=dict)


class GuardrailedAgent:
    def __init__(
        self,
        tools: Tools,
        policy: PolicyConfig,
        deterministic: DeterministicPolicy,
        injection: PromptInjectionPolicy,
        model_based: ModelBasedPolicy,
        pii: PIIMiddleware,
    ):
        self.tools = tools
        self.policy = policy
        self.deterministic = deterministic
        self.injection = injection
        self.model_based = model_based
        self.pii = pii

    def _route_tool(self, user_text: str) -> Optional[Tuple[str, Dict[str, str]]]:
        t = (user_text or "").lower()

        if "send email" in t:
            return "send_email", {
                "to": "team@company.com",
                "subject": "Q4 Results",
                "body": user_text,
            }

        if "delete" in t and "record" in t:
            return "delete_records", {
                "table": "user",
                "where": "1=1",
            }

        if "lookup" in t and "customer" in t:
            return "customer_lookup", {"query": user_text}

        if "search" in t or "web" in t:
            return "search_web", {"query": user_text}

        return None

    def run(self, user_text: str, approvals: Dict[str, bool]) -> Tuple[str, List[TraceEvent], Dict[str, Any], AuditRecord]:
        trace: List[TraceEvent] = []
        meta: Dict[str, Any] = {}
        risk = RiskScore()
        triggered_policies: List[str] = []
        processed_input = user_text

        blocked, hits = self.deterministic.check(user_text)
        if hits:
            risk.add(35, f"Deterministic banned keywords: {hits}")
            triggered_policies.append("deterministic_keywords")
            trace.append(TraceEvent("before_agent:deterministic", "flagged", f"Matched keywords: {hits}"))
        else:
            trace.append(TraceEvent("before_agent:deterministic", "clear", "No banned keywords matched."))

        inj_block, inj_hits = self.injection.check(user_text)
        if inj_hits:
            risk.add(40, f"Prompt injection patterns: {inj_hits}")
            triggered_policies.append("prompt_injection")
            trace.append(TraceEvent("before_agent:prompt_injection", "flagged", f"Matched patterns: {inj_hits}"))
        else:
            trace.append(TraceEvent("before_agent:prompt_injection", "clear", "No prompt injection pattern found."))

        label, expl = self.model_based.classify(user_text)
        trace.append(TraceEvent("before_agent:model_based", label, expl))
        if label == "unsafe":
            risk.add(30, "Model-based classifier marked input unsafe.")
            triggered_policies.append("model_based_input")

        processed_input, notes, pii_block, pii_triggers = self.pii.process(user_text, is_input=True)
        for n in notes:
            trace.append(TraceEvent("pii:input", "note", n))
        if pii_triggers:
            risk.add(20, f"PII detected in input: {pii_triggers}")
            triggered_policies.extend(pii_triggers)

        if pii_block:
            final = "🚫 Blocked by PII input policy."
            trace.append(TraceEvent("decision", "blocked", final))
            audit = AuditRecord(
                timestamp_utc=AuditRecord.now(),
                user_input=user_text,
                processed_input=processed_input,
                final_output=final,
                final_decision="blocked",
                risk_score=risk.to_dict(),
                triggered_policies=triggered_policies,
                trace=[asdict(t) for t in trace],
            )
            return final, trace, meta, audit

        tool_used = None
        tool_args: Dict[str, Any] = {}
        tool_result: Optional[ToolResult] = None
        tool_call = self._route_tool(processed_input)

        if tool_call:
            tool_used, tool_args = tool_call
            trace.append(TraceEvent("agent:tool_routing", "selected", f"Tool selected: {tool_used}", {"args": tool_args}))
            tool_risk = self.policy.tool_risk_levels.get(tool_used, 0)
            risk.add(tool_risk, f"Tool selected: {tool_used}")

            if risk.total >= self.policy.block_threshold:
                final = "🚫 Blocked due to high composite risk score."
                trace.append(TraceEvent("decision", "blocked", final, {"risk": risk.total}))
                audit = AuditRecord(
                    timestamp_utc=AuditRecord.now(),
                    user_input=user_text,
                    processed_input=processed_input,
                    final_output=final,
                    final_decision="blocked",
                    risk_score=risk.to_dict(),
                    triggered_policies=triggered_policies,
                    trace=[asdict(t) for t in trace],
                    tool_used=tool_used,
                    tool_args=tool_args,
                )
                return final, trace, meta, audit

            require_approval = (
                self.policy.hitl_require_approval.get(tool_used, False)
                or risk.total >= self.policy.review_threshold
            )

            if require_approval and not approvals.get(tool_used, False):
                final = f"⏸️ Paused for human approval before {tool_used}."
                meta["paused_tool"] = tool_used
                meta["paused_args"] = tool_args
                trace.append(TraceEvent("hitl", "paused", final, {"risk": risk.total}))
                audit = AuditRecord(
                    timestamp_utc=AuditRecord.now(),
                    user_input=user_text,
                    processed_input=processed_input,
                    final_output=final,
                    final_decision="paused_for_approval",
                    risk_score=risk.to_dict(),
                    triggered_policies=triggered_policies,
                    trace=[asdict(t) for t in trace],
                    tool_used=tool_used,
                    tool_args=tool_args,
                )
                return final, trace, meta, audit

            fn = getattr(self.tools, tool_used)
            tool_result = fn(**tool_args)
            trace.append(TraceEvent("tool:execute", "ok", tool_result.output))

        if tool_result:
            output = f"✅ Request processed.\n\nTool output:\n{tool_result.output}"
        else:
            output = f"✅ Request processed.\n\nEcho (sanitized input): {processed_input}"

        processed_output, output_notes, output_blocked, output_triggers = self.pii.process(output, is_input=False)
        for n in output_notes:
            trace.append(TraceEvent("pii:output", "note", n))
        if output_triggers:
            triggered_policies.extend(output_triggers)

        if output_blocked:
            final = "🚫 Output blocked by PII output policy."
            trace.append(TraceEvent("after_agent:pii", "blocked", final))
            audit = AuditRecord(
                timestamp_utc=AuditRecord.now(),
                user_input=user_text,
                processed_input=processed_input,
                final_output=final,
                final_decision="blocked",
                risk_score=risk.to_dict(),
                triggered_policies=triggered_policies,
                trace=[asdict(t) for t in trace],
                tool_used=tool_used,
                tool_args=tool_args,
            )
            return final, trace, meta, audit

        out_label, out_expl = self.model_based.classify(processed_output)
        trace.append(TraceEvent("after_agent:model_based", out_label, out_expl))
        if out_label == "unsafe":
            final = "⚠️ Unsafe output was intercepted and replaced with a compliant response."
            trace.append(TraceEvent("after_agent:mutation", "mutated", final))
            processed_output = final
            triggered_policies.append("model_based_output")

        trace.append(TraceEvent("decision", "allowed", "Response delivered."))

        audit = AuditRecord(
            timestamp_utc=AuditRecord.now(),
            user_input=user_text,
            processed_input=processed_input,
            final_output=processed_output,
            final_decision="allowed",
            risk_score=risk.to_dict(),
            triggered_policies=triggered_policies,
            trace=[asdict(t) for t in trace],
            tool_used=tool_used,
            tool_args=tool_args,
        )

        return processed_output, trace, meta, audit