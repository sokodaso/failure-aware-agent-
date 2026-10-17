"""Query-side sentence embedding."""


class Embedder:
    """Lazily loads a sentence-transformers model. For a graph's own embeddings use the model that built them
    (`Graph.embedding_model`)."""

    def __init__(self, model_name: str):
        self.model_name = model_name
        self._model = None

    def encode(self, text: str) -> list[float]:
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        return [float(x) for x in self._model.encode(text, normalize_embeddings=True)]
