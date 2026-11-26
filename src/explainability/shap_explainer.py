import numpy as np
from typing import Dict, Any, List, Optional
import shap
from src.ml.model_inference import ForensicModelInference
from src.preprocessing.text_cleaner import clean_log_text

SHAP_CAVEAT = (
    "Caveat: SHAP attribution identifies statistical token contributions for this model prediction. "
    "It does not establish attacker intent, causation, or legal guilt."
)

class ForensicShapExplainer:
    """
    Computes local feature importance and token attributions for individual log classifications
    using TreeExplainer on the fitted Random Forest classifier.
    """
    _explainer = None
    _vectorizer = None
    _classifier = None
    _feature_names = None
    _classes = None

    @classmethod
    def _initialize_explainer(cls):
        pipeline, meta = ForensicModelInference.load_model()
        if pipeline is None:
            return False

        cls._vectorizer = pipeline.named_steps["tfidf"]
        cls._classifier = pipeline.named_steps["clf"]
        cls._feature_names = np.array(cls._vectorizer.get_feature_names_out())
        cls._classes = list(pipeline.classes_)

        try:
            cls._explainer = shap.TreeExplainer(cls._classifier)
            return True
        except Exception:
            return False

    @classmethod
    def explain_log_event(cls, text: str, top_k: int = 8) -> Dict[str, Any]:
        """
        Generate feature attributions and token contributions for a given log text.
        """
        if cls._explainer is None:
            ok = cls._initialize_explainer()
            if not ok:
                return {
                    "status": "EXPLAINER_UNAVAILABLE",
                    "tokens": [],
                    "top_positive": [],
                    "top_negative": [],
                    "rationale": "SHAP explainer unavailable because the model pipeline is not yet trained.",
                    "caveat": SHAP_CAVEAT,
                }

        cleaned = clean_log_text(str(text or ""))
        if not cleaned:
            return {
                "status": "EMPTY_INPUT",
                "tokens": [],
                "top_positive": [],
                "top_negative": [],
                "rationale": "Log text is empty. No features to attribute.",
                "caveat": SHAP_CAVEAT,
            }

        # Vectorize input
        X_vec = cls._vectorizer.transform([cleaned]).toarray()
        non_zero_indices = np.where(X_vec[0] > 0)[0]

        if len(non_zero_indices) == 0:
            return {
               "status": "INSUFFICIENT_VOCABULARY",
                "tokens": [],
                "top_positive": [],
                "top_negative": [],
                "rationale": "Input tokens do not intersect with the model vocabulary.",
                "caveat": SHAP_CAVEAT,
            }

        # Target class index for "suspicious"
        suspicious_idx = cls._classes.index("suspicious") if "suspicious" in cls._classes else 1

        try:
            # Compute SHAP values
            raw_shap = cls._explainer.shap_values(X_vec)

            # Handle different SHAP return formats across library versions
            if isinstance(raw_shap, list):
                # list of [class_0_array, class_1_array]
                values = raw_shap[suspicious_idx][0]
            elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 3:
                # shape: (n_samples, n_features, n_classes)
                values = raw_shap[0, :, suspicious_idx]
            elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 2:
                values = raw_shap[0]
            else:
                values = np.array(raw_shap)[0]

            # Collect non-zero active feature contributions
            attributions = []
            for idx in non_zero_indices:
                feature_name = cls._feature_names[idx]
                contrib = float(values[idx])
                attributions.append({
                    "feature": feature_name,
                    "contribution": round(contrib, 4),
                    "tf_idf_weight": round(float(X_vec[0, idx]), 4),
                    "impact": "SUSPICIOUS" if contrib > 0 else "NORMAL"
                })

            # Sort by absolute contribution magnitude
            attributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)

            top_positive = [a for a in attributions if a["contribution"] > 0][:top_k]
            top_negative = [a for a in attributions if a["contribution"] < 0][:top_k]

            # Generate natural language summary
            pos_tokens = [f"'{a['feature']}' (+{a['contribution']})" for a in top_positive[:3]]
            neg_tokens = [f"'{a['feature']}' ({a['contribution']})" for a in top_negative[:3]]

            if top_positive:
                pos_str = ", ".join(pos_tokens)
                rationale = f"Prediction pushed towards SUSPICIOUS primarily by tokens: {pos_str}."
            else:
                rationale = "No strong suspicious indicators detected in token vocabulary."

            if top_negative:
                neg_str = ", ".join(neg_tokens)
                rationale += f" Counter-balanced towards NORMAL by tokens: {neg_str}."

            return {
                "status": "SUCCESS",
                "tokens": attributions[:top_k],
                "top_positive": top_positive,
                "top_negative": top_negative,
                "rationale": rationale,
                "caveat": SHAP_CAVEAT,
                "explainer_type": "shap.TreeExplainer (RandomForest)",
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "tokens": [],
                "top_positive": [],
                "top_negative": [],
                "rationale": f"SHAP calculation error: {str(e)}",
                "caveat": SHAP_CAVEAT,
            }
