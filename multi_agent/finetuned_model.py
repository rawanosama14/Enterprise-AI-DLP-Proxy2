import logging
from typing import Dict, Any, List
from transformers import pipeline
from config import NER_MODEL_NAME, CONFIDENCE_THRESHOLD

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FineTunedPIIModel:
    """
    Layer-2 Neural Context & Unstructured PII Detection Engine.
    Uses Transformer-based Token Classification (NER) to extract contextual PII
    (Persons, Organizations, Locations) that deterministic Regex cannot capture.
    """
    def __init__(self, model_path: str = NER_MODEL_NAME):
        self.model_name = model_path
        self.confidence_threshold = CONFIDENCE_THRESHOLD
        self.ner_pipeline = None
        
        try:
            # Loads HuggingFace model or local fine-tuned LoRA/checkpoint
            self.ner_pipeline = pipeline(
                "ner",
                model=self.model_name,
                aggregation_strategy="simple"
            )
            logger.info(f"Loaded Neural NER Model: {self.model_name}")
        except Exception as e:
            # Fallback آمن تماماً عشان التطبيق مايعملش Crash والشاشة تفتح
            self.ner_pipeline = None
            logger.warning(f"Warning: Neural NER pipeline disabled due to network restriction: {e}")
        self.label_mapping = {
            "PER": "PERSON",
            "PERSON": "PERSON",
            "ORG": "ORGANIZATION",
            "LOC": "LOCATION"
        }

    def predict_and_mask_pii(self, text: str) -> Dict[str, Any]:
        """
        Executes neural inference to extract and mask unstructured entities.
        """
        if self.ner_pipeline is None:
            raise RuntimeError("Neural NER model is not initialized.")

        raw_predictions = self.ner_pipeline(text)
        detected_entities: List[Dict[str, Any]] = []
        sanitized_text = text

        # Sort entities in reverse order by character span to replace accurately without shifting indices
        valid_preds = [
            p for p in raw_predictions 
            if float(p.get("score", 0.0)) >= self.confidence_threshold
        ]
        valid_preds.sort(key=lambda x: x["start"], reverse=True)

        confidences = []
        for pred in valid_preds:
            raw_label = pred.get("entity_group", "UNK")
            mapped_label = self.label_mapping.get(raw_label, raw_label)
            entity_val = pred["word"].strip()
            score = float(pred["score"])

            # Skip partial subword artifacts or already redacted placeholders
            if len(entity_val) < 2 or entity_val.startswith("[") or "#" in entity_val:
                continue

            confidences.append(score)
            detected_entities.append({
                "entity_type": mapped_label,
                "value": entity_val,
                "confidence": round(score, 4),
                "source": "Layer2_Neural_NER"
            })

            start_idx, end_idx = pred["start"], pred["end"]
            sanitized_text = (
                sanitized_text[:start_idx] + f"[{mapped_label}]" + sanitized_text[end_idx:]
            )

        avg_confidence = round(sum(confidences) / len(confidences), 4) if confidences else 1.0

        return {
            "model_used": self.model_name,
            "confidence_score": avg_confidence,
            "detected_entities": list(reversed(detected_entities)),
            "sanitized_text": sanitized_text
        }