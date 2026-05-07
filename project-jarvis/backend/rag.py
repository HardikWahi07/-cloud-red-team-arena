import faiss
import numpy as np
from typing import List, Dict

class SimpleRAG:
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.index = faiss.IndexFlatL2(dimension)
        self.documents = []

    def add_document(self, text: str, metadata: Dict = None):
        # In a real system, we'd use an embedding model like SentenceTransformers
        # For this MVP, we'll use a deterministic mock embedding for speed/portability
        embedding = self._mock_embedding(text)
        self.index.add(np.array([embedding]).astype('float32'))
        self.documents.append({"text": text, "metadata": metadata or {}})

    def query(self, text: str, k: int = 3) -> List[Dict]:
        if not self.documents:
            return []
        embedding = self._mock_embedding(text)
        distances, indices = self.index.search(np.array([embedding]).astype('float32'), k)

        results = []
        for idx in indices[0]:
            if idx != -1 and idx < len(self.documents):
                results.append(self.documents[idx])
        return results

    def _mock_embedding(self, text: str) -> np.ndarray:
        # Create a deterministic mock embedding based on the text hash
        import hashlib
        h = hashlib.sha256(text.encode()).digest()
        vec = np.frombuffer(h, dtype=np.uint8).astype(np.float32)
        # Pad or truncate to desired dimension
        if len(vec) < self.dimension:
            vec = np.pad(vec, (0, self.dimension - len(vec)))
        else:
            vec = vec[:self.dimension]
        return vec / np.linalg.norm(vec)
