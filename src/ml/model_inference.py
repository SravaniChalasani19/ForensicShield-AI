import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import joblib
from config import MODELS_DIR, MODEL_VERSION, CONFIDENCE_THRESHOLD
from src.preprocessing.text_cleaner import clean_log_text

MODEL_PIPELINE_PATH = MODELS_DIR / "forensicshield_rf_pipeline.joblib"
MODEL_METADATA_PATH = MODELS_DIR / "model_metadata.json"

class ForensicModelInference:
    """
    Loads fitted Random Forest pipeline and executes inference on normalized log text.
    Handles un-trained state gracefully without throwing unhandled exceptions.
    """
    _pipeline = None
    _metadata = None

    @classmethod
    def is_model_ready(cls) -> bool:
        return MODEL_PIPELINE_PATH.exists() and MODEL_METADATA_PATH.exists()

    @classmethod
    def load_model(cls, force_reload: bool = False):
        if cls._pipeline is not None and not force_reload:
            return cls._pipeline, cls._metadata

        if not cls.is_model_ready():
            return None, None

        try:
            cls._pipeline = joblib.load(MODEL_PIPELINE_PATH)
            with open(MODEL_METADATA_PATH, "r", encoding="utf-8") as f:
                cls._metadata = json.load(f)
            return cls._pipeline, cls._metadata
        except Exception:
            return None, None

    @classmethod
    def predict_single(cls, text: str) -> Dict[str, Any]:
        """Classify a single log text entry."""
        pipeline, meta = cls.load_model()
        if pipeline is None:
            return {
                "status": "MODEL_NOT_TRAINED",
                "predicted_label": None,
                "score": None,
                "model_version": None,
                "message": "Model not trained. Train the pipeline before running inference."
            }

        cleaned = clean_log_text(str(text or "")).strip()
        if not cleaned:
            return {
                "status": "SUCCESS",
                "predicted_label": "normal",
                "score": 0.0,
                "model_version": meta.get("model_version", MODEL_VERSION),
            }

        # Check if input has any intersecting features with model vocabulary
        vec = pipeline.named_steps["tfidf"]
        X_vec = vec.transform([cleaned])
        if X_vec.nnz == 0:
            return {
                "status": "SUCCESS",
                "predicted_label": "normal",
                "score": 0.0,
                "model_version": meta.get("model_version", MODEL_VERSION),
            }

        # Predict probability
        classes = list(pipeline.classes_)
        clf = pipeline.named_steps["clf"]
        proba = clf.predict_proba(X_vec)[0]

        suspicious_idx = classes.index("suspicious") if "suspicious" in classes else 1
        suspicious_score = float(proba[suspicious_idx])
        predicted_label = "suspicious" if suspicious_score >= CONFIDENCE_THRESHOLD else "normal"

        return {
            "status": "SUCCESS",
            "predicted_label": predicted_label,
            "score": round(suspicious_score, 4),
            "model_version": meta.get("model_version", MODEL_VERSION),
        }

    
    @classmethod
    def predict_batch(cls, texts: List[str]) -> List[Dict[str, Any]]:
        """Efficient batch inference using the existing trained model."""

        pipeline, meta = cls.load_model()

        if pipeline is None:
            return [{
                "status": "MODEL_NOT_TRAINED",
                "predicted_label": None,
                "score": None,
                "model_version": None,
            } for _ in texts]

        if not texts:
            return []

        results = []
        batch_size = 2000

        vec = pipeline.named_steps["tfidf"]
        clf = pipeline.named_steps["clf"]

        classes = list(pipeline.classes_)
        suspicious_idx = classes.index("suspicious")

        version = meta.get("model_version", MODEL_VERSION)

        for start in range(0, len(texts), batch_size):

            batch = texts[start:start + batch_size]

            cleaned = [
                clean_log_text(str(t or "")).strip()
                for t in batch
            ]

            X = vec.transform(cleaned)
            probabilities = clf.predict_proba(X)
            feature_counts = X.getnnz(axis=1)

            for i in range(len(batch)):

                has_features = bool(feature_counts[i])

                score = (
                    float(probabilities[i][suspicious_idx])
                    if has_features else 0.0
                )

                label = (
                    "suspicious"
                    if score >= CONFIDENCE_THRESHOLD
                    else "normal"
                )

                results.append({
                    "status": "SUCCESS",
                    "predicted_label": label,
                    "score": round(score, 4),
                    "model_version": version,
                    "vocabulary_match": has_features,
                })

        return results

