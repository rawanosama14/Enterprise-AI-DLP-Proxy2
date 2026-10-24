from typing import TypedDict, List, Dict, Any, Optional

class DLPState(TypedDict):
    """
    Centralized State Schema for Multi-Agent AI DLP Security Proxy.
    Tracks payload transformation, latency metrics, risk scores, and failover status across execution nodes.
    """
    # 1. Payload Tracking
    request_id: str
    timestamp: str
    raw_text: str
    pre_filtered_text: str
    pre_filter_triggered: bool
    
    # 2. Entity & Context Detection
    detected_entities: List[Dict[str, Any]]
    contains_sensitive_data: bool
    risk_score: float                       # Risk score evaluation (0 to 100)
    risk_level: str                         # CRITICAL, HIGH, MEDIUM, LOW
    
    # 3. Masking Agent Telemetry
    masked_text: Optional[str]
    masker_execution_time: float
    masker_error: Optional[str]
    
    # 4. RAG Policy & Shadow Agent Auditing
    rag_policy_violations: List[str]        # Policy violation alerts from RAG Engine
    
    # 5. Circuit Breaker & Failover Control
    failover_triggered: bool
    failover_reason: Optional[str]
    
    # 6. Final Secured Output Payload
    final_sanitized_text: str