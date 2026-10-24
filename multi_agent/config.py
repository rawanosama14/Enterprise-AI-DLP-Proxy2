import os

# --- Performance & SLA Thresholds ---
MASKER_TIMEOUT_SECONDS = 2.5
MAX_RETRIES = 2

# --- Model & RAG Configurations (For Research Reproducibility) ---
NER_MODEL_NAME = os.getenv("DLP_NER_MODEL", "dslim/bert-base-NER")
ZERO_SHOT_MODEL_NAME = os.getenv("DLP_CONTEXT_MODEL", "facebook/bart-large-mnli")
EMBEDDING_MODEL_NAME = os.getenv("DLP_EMBED_MODEL", "all-MiniLM-L6-v2")

CONFIDENCE_THRESHOLD = 0.80
RAG_SIMILARITY_THRESHOLD = 0.55  # Cosine similarity threshold for policy violation

# --- PII & Sensitive Entity Classification ---
DEFAULT_PII_TYPES = [
    "PHONE_NUMBER", 
    "EMAIL_ADDRESS", 
    "CREDIT_CARD", 
    "IP_ADDRESS", 
    "PERSON", 
    "ORGANIZATION",
    "LOCATION",
    "SECRET_KEY",
    "MEDICAL_RECORD",
    "FINANCIAL_CONTEXT"
]

# Risk Severity Scoring
ENTITY_RISK_LEVELS = {
    "SECRET_KEY": "CRITICAL",
    "AWS_SECRET_KEY": "CRITICAL",
    "GENERIC_API_KEY": "CRITICAL",
    "JWT_TOKEN": "CRITICAL",
    "SSH_PRIVATE_KEY": "CRITICAL",
    "DATABASE_URL": "CRITICAL",
    "EXPLICIT_PASSWORD": "CRITICAL",
    "CREDIT_CARD": "HIGH",
    "MEDICAL_RECORD": "HIGH",
    "MEDICAL_DIAGNOSIS": "HIGH",
    "FINANCIAL_CONTEXT": "HIGH",
    "PHONE_NUMBER": "MEDIUM",
    "EMAIL_ADDRESS": "MEDIUM",
    "IP_ADDRESS": "LOW",
    "PERSON": "LOW",
    "ORGANIZATION": "LOW",
    "LOCATION": "LOW"
}

RISK_WEIGHTS = {
    "CRITICAL": 50,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5
}

# --- System & Failover Guardrails ---
FAILOVER_POLICY = "STRICT_REDACTION"
ENABLE_AUDIT_LOGGING = True