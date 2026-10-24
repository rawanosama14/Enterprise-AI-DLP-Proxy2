import chromadb
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any
from config import EMBEDDING_MODEL_NAME, RAG_SIMILARITY_THRESHOLD

class VectorRAGPolicyEngine:
    """
    Layer-3 Semantic Policy Auditing Engine using ChromaDB & Sentence Embeddings.
    Audits prompts against enterprise security policies via cosine similarity.
    """
    def __init__(self):
        self.embedder = SentenceTransformer(EMBEDDING_MODEL_NAME)
        self.client = chromadb.Client()
        self.collection = self.client.get_or_create_collection(
            name="enterprise_dlp_policies",
            metadata={"hnsw:space": "cosine"}
        )
        self._seed_default_policies()

    def _seed_default_policies(self):
        """Populates vector store with baseline Enterprise Security Policies."""
        if self.collection.count() == 0:
            policies = [
                "Policy 101 (Healthcare HIPAA): Sharing patient medical history, clinical diagnoses, diseases, or prescribed treatments is strictly prohibited.",
                "Policy 102 (Financial Confidentiality): Disclosing internal corporate budgets, mergers, executive salaries, or unpublished financial projections is forbidden.",
                "Policy 103 (Intellectual Property & Source Code): Transmitting proprietary algorithms, internal architecture secrets, or production credentials violates security policy."
            ]
            ids = ["POL-101", "POL-102", "POL-103"]
            embeddings = self.embedder.encode(policies).tolist()
            self.collection.add(
                documents=policies,
                embeddings=embeddings,
                ids=ids
            )

    def audit_prompt(self, text: str) -> List[str]:
        """
        Computes semantic similarity between input prompt and security policies.
        Returns a list of violated policy descriptions.
        """
        if not text.strip():
            return []

        query_embedding = self.embedder.encode([text]).tolist()
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=2
        )

        violations = []
        if results and results["distances"] and results["documents"]:
            for distance, doc, pol_id in zip(
                results["distances"][0], results["documents"][0], results["ids"][0]
            ):
                # In ChromaDB cosine space: similarity = 1 - distance
                similarity = 1.0 - float(distance)
                if similarity >= RAG_SIMILARITY_THRESHOLD:
                    violations.append(
                        f"Violation of {pol_id} (Semantic Similarity: {similarity:.2f}): {doc}"
                    )

        return violations