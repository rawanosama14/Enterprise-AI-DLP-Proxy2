import re
from typing import Dict, Any, List

class PreFilterEngine:
    """
    Layer-1 Security Guardrail Engine:
    Executes high-speed, deterministic Regex pattern matching for Critical Secrets,
    API Keys, Infrastructure Credentials, and Structured PII.
    """
    def __init__(self):
        # 1. Critical Infrastructure & Secret Patterns
        self.secret_patterns = {
            "PATIENT_RECORD_ID": r"PATIENT_RECORD_ID=[A-Za-z0-9\-_]+",
            "AWS_SECRET_KEY": r"(?i)(?:aws_secret_access_key|aws_access_key_id)\s*=\s*[A-Za-z0-9/+=]{16,40}",
            "GENERIC_API_KEY": r"(?i)(?:api[_-]?key|secret[_-]?key)\s*=\s*[A-Za-z0-9_\-]{8,64}",
            "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "DATABASE_URL": r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[^\s]+",
            "SSH_PRIVATE_KEY": r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
            "EXPLICIT_PASSWORD": r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]"
        }

        # 2. Structured PII Patterns
        self.structured_pii_patterns = {
            "EMAIL_ADDRESS": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "PHONE_NUMBER": r"\b\d{3}[-.\s]?\d{2,3}[-.\s]?\d{4}\b",
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
            "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        }

    def scan_and_redact(self, text: str) -> Dict[str, Any]:
        """
        Scans input text for critical secret tokens and structured PII.
        Returns sanitization status, updated payload, and detected entities.
        """
        triggered = False
        sanitized_text = text
        intercepted_secrets: List[str] = []
        detected_entities: List[Dict[str, Any]] = []

        # Scan for critical secrets
        for key_type, pattern in self.secret_patterns.items():
            for match in re.finditer(pattern, sanitized_text):
                triggered = True
                val = match.group(0)
                intercepted_secrets.append(key_type)
                detected_entities.append({
                    "entity_type": "SECRET_KEY",
                    "sub_type": key_type,
                    "value": val,
                    "confidence": 1.0,
                    "source": "Layer1_Regex"
                })
            sanitized_text = re.sub(pattern, "[SECRET_KEY_REDACTED]", sanitized_text)

        # Scan for structured PII
        for pii_type, pattern in self.structured_pii_patterns.items():
            for match in re.finditer(pattern, sanitized_text):
                val = match.group(0)
                detected_entities.append({
                    "entity_type": pii_type,
                    "value": val,
                    "confidence": 1.0,
                    "source": "Layer1_Regex"
                })
            sanitized_text = re.sub(pattern, f"[{pii_type}]", sanitized_text)

        return {
            "triggered": triggered,
            "intercepted_secrets": intercepted_secrets,
            "detected_entities": detected_entities,
            "total_secrets_found": len(intercepted_secrets),
            "sanitized_text": sanitized_text
        }