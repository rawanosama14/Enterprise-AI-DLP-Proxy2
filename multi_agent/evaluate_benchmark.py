import time
import numpy as np
from dlp_system import run_dlp_pipeline

# Sample Benchmark Dataset (Can be expanded or linked to HuggingFace 'ai4privacy/pii-masking-200k')
BENCHMARK_SAMPLES = [
    {
        "text": "PATIENT_RECORD_ID=PR-99812-US. Patient Sarah Jenkins was diagnosed with Type 2 Diabetes. SSN: 987-65-4321. Email: s.jenkins@healthmail.net.",
        "ground_truth_entities": ["PR-99812-US", "Sarah Jenkins", "987-65-4321", "s.jenkins@healthmail.net"],
        "has_policy_violation": True
    },
    {
        "text": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE. Contact Engineer Alex Rivera at alex.r@corp.io or 555-234-5678 regarding the server migration.",
        "ground_truth_entities": ["AKIAIOSFODNN7EXAMPLE", "Alex Rivera", "alex.r@corp.io", "555-234-5678"],
        "has_policy_violation": True
    },
    {
        "text": "Dr. Michael Scott from Acme Corp met with John Doe in New York to discuss the confidential Q4 corporate budget projections.",
        "ground_truth_entities": ["Michael Scott", "Acme Corp", "John Doe", "New York"],
        "has_policy_violation": True
    },
    {
        "text": "Can you explain how a binary search tree works in Python with a simple code example?",
        "ground_truth_entities": [],
        "has_policy_violation": False
    }
]

def evaluate_mode(mode_name: str):
    tp, fp, fn = 0, 0, 0
    latencies = []

    for sample in BENCHMARK_SAMPLES:
        start = time.perf_counter()
        result = run_dlp_pipeline(sample["text"], ablation_mode=mode_name)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

        predicted_values = [e["value"] for e in result["detected_entities"]]
        truth_values = sample["ground_truth_entities"]

        # Entity-level matching (Substring/Overlap match)
        matched_truth = set()
        for pred in predicted_values:
            match_found = False
            for idx, truth in enumerate(truth_values):
                if pred in truth or truth in pred:
                    match_found = True
                    matched_truth.add(idx)
                    break
            if match_found:
                tp += 1
            else:
                fp += 1

        fn += (len(truth_values) - len(matched_truth))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_latency = np.mean(latencies)

    return {
        "Architecture Variant": mode_name,
        "Precision": round(precision * 100, 2),
        "Recall": round(recall * 100, 2),
        "F1-Score": round(f1 * 100, 2),
        "Avg Latency (ms)": round(avg_latency, 2)
    }

if __name__ == "__main__":
    print("\n--- Running Scientific Ablation Study for AI DLP Proxy ---")
    modes = ["regex_only", "neural_only", "full"]
    print(f"{'Variant':<15} | {'Precision (%)':<14} | {'Recall (%)':<12} | {'F1-Score (%)':<14} | {'Latency (ms)':<12}")
    print("-" * 78)
    for m in modes:
        metrics = evaluate_mode(m)
        print(f"{metrics['Architecture Variant']:<15} | {metrics['Precision']:<14} | {metrics['Recall']:<12} | {metrics['F1-Score']:<14} | {metrics['Avg Latency (ms)']:<12}")