import time
from typing import Dict, Any, Optional
from config import ENTITY_RISK_LEVELS, RISK_WEIGHTS, MASKER_TIMEOUT_SECONDS
from pre_filter import PreFilterEngine
from finetuned_model import FineTunedPIIModel
from vector_rag import VectorRAGPolicyEngine

# Initialize Singleton Engines once to avoid reloading models on every request
pre_filter_engine = PreFilterEngine()
neural_pii_engine = FineTunedPIIModel()
rag_policy_engine = VectorRAGPolicyEngine()


def calculate_risk_score(detected_entities: list, rag_violations: list) -> int:
    """
    Mathematical Risk Scoring Model:
    R(x) = min(100, sum(w_i) + 40 * I(rag_violation))
    """
    score = 0
    for entity in detected_entities:
        entity_type = entity.get("sub_type") or entity.get("entity_type", "LOW")
        risk_tier = ENTITY_RISK_LEVELS.get(entity_type, "LOW")
        score += RISK_WEIGHTS.get(risk_tier, 5)

    if rag_violations:
        score += 40

    return min(score, 100)


def run_dlp_pipeline(
    raw_text: str,
    sim_mode: Optional[str] = None,
    ablation_mode: str = "full"  # Options: 'regex_only', 'neural_only', 'full'
) -> Dict[str, Any]:
    """
    Executes the Multi-Agent AI DLP Security Proxy Pipeline.
    Supports 'ablation_mode' for scientific benchmarking.
    """
    # 0. Emergency Circuit Breaker (Fault-Injection Crash Test)
    if sim_mode == "error":
        return {
            "raw_text": raw_text,
            "pre_filtered_text": raw_text,
            "pre_filter_triggered": True,
            "detected_entities": [],
            "risk_score": 100,
            "masker_execution_time": 0.0,
            "rag_policy_violations": ["System Crash Fault-Injection Intercepted"],
            "failover_triggered": True,
            "failover_reason": "Injected Exception / Service Crash Detected",
            "final_sanitized_text": "[FAILOVER_ACTIVE] Emergency Circuit Breaker Redacted Payload"
        }

    pipeline_start = time.perf_counter()
    detected_entities = []
    pre_filter_triggered = False
    current_text = raw_text

    # 1. Layer-1: Deterministic Pre-Filtering Agent
    if ablation_mode in ["regex_only", "full"]:
        l1_res = pre_filter_engine.scan_and_redact(current_text)
        pre_filter_triggered = l1_res["triggered"]
        current_text = l1_res["sanitized_text"]
        detected_entities.extend(l1_res["detected_entities"])

    pre_filtered_text = current_text

    # 2. Layer-2: Neural Context & PII Detection Agent (with Circuit Breaker)
    failover_triggered = False
    failover_reason = ""
    rag_violations = []

    if ablation_mode in ["neural_only", "full"]:
        try:
            if sim_mode == "timeout":
                time.sleep(MASKER_TIMEOUT_SECONDS + 0.1)

            l2_res = neural_pii_engine.predict_and_mask_pii(current_text)
            current_text = l2_res["sanitized_text"]
            detected_entities.extend(l2_res["detected_entities"])
        except Exception as e:
            failover_triggered = True
            failover_reason = f"Layer-2 Neural Engine Exception: {str(e)}"
            current_text = "[FAILOVER_ACTIVE] Payload Blocked Due to Neural Engine Fault"

    # 3. Layer-3: Vector RAG Semantic Policy Engine
    if ablation_mode == "full" and not failover_triggered:
        rag_violations = rag_policy_engine.audit_prompt(raw_text)

    masker_time = time.perf_counter() - pipeline_start

    # 4. SLA & Shadow Agent Verification Guardrail
    if masker_time > MASKER_TIMEOUT_SECONDS:
        failover_triggered = True
        failover_reason = f"Latency SLA Exceeded ({masker_time:.3f}s > {MASKER_TIMEOUT_SECONDS}s)"
    elif sim_mode == "hallucination":
        failover_triggered = True
        failover_reason = "Shadow Agent Alert: Unmasked PII Leak Detected in Output"
        rag_violations.append("Violation of Policy 101: Data Leakage in Model Output")

    if rag_violations and not failover_triggered:
        failover_triggered = True
        failover_reason = f"RAG Security Policy Violation: {rag_violations[0]}"

    risk_score = calculate_risk_score(detected_entities, rag_violations)

    return {
        "raw_text": raw_text,
        "pre_filtered_text": pre_filtered_text,
        "pre_filter_triggered": pre_filter_triggered,
        "detected_entities": detected_entities,
        "risk_score": risk_score,
        "masker_execution_time": masker_time,
        "rag_policy_violations": rag_violations,
        "failover_triggered": failover_triggered,
        "failover_reason": failover_reason,
        "final_sanitized_text": current_text
    }