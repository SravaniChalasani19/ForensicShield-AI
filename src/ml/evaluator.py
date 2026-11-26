import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from config import REPORTS_DIR
from src.ml.model_inference import ForensicModelInference

EVAL_OUTPUT_DIR = REPORTS_DIR / "evaluation"
EVAL_SUMMARY_PATH = EVAL_OUTPUT_DIR / "evaluation_summary.json"

class ForensicEvaluator:
    """
    Computes rigorous empirical evaluation metrics on genuinely labeled test records.
    Never fabricates metrics; explicitly outputs NOT_EVALUATED when true labels are missing.
    """

    @classmethod
    def get_evaluation_status(cls) -> Dict[str, Any]:
        """Return evaluation metrics and independent validation status."""

        if EVAL_SUMMARY_PATH.exists():
            try:
                with open(EVAL_SUMMARY_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)

                data["external_benchmark_status"] = "NOT_EVALUATED"

                data["external_benchmark_message"] = (
                    "Independent anti-forensic validation is pending. "
                    "External datasets have been acquired and analyzed. "
                    "Independent record-level anti-forensic labels "
                    "remain unavailable."
                )

                if data.get("dataset_name") == "Cleaned Synthetic Held-Out Test Dataset":
                    data["evaluation_type"] = "PRELIMINARY_SYNTHETIC_EVALUATION"
                    data["evaluation_notice"] = (
                        "Evaluated on 29 held-out synthetic records. "
                        "Exact train-test overlap is zero. "
                        "Similar-template leakage risk remains. "
                        "Results do not establish real-world performance."
                    )

                elif data.get("dataset_name") == "Controlled Software Test Fixtures":
                    data["evaluation_type"] = "SOFTWARE_FIXTURE_TEST"

                return data

            except Exception:
                pass

        return {
            "evaluated": False,
            "status": "NOT_EVALUATED",
            "external_benchmark_status": "NOT_EVALUATED",
            "message": "No valid evaluation results available.",
            "metrics": None,
            "required_action": "Run a verified evaluation."
        }

    @classmethod
    def evaluate_records(
        cls,
        records: List[Dict[str, Any]],
        dataset_name: str = "Test Set",
        save_result: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluate trained model against a labeled list of canonical record dicts.
        """
        if not ForensicModelInference.is_model_ready():
            return {
                "evaluated": False,
                "status": "MODEL_NOT_TRAINED",
                "message": "Evaluation aborted: detection model is not trained.",
            }

        valid_pairs = []
        for r in records:
            gt = r.get("ground_truth_label")
            txt = r.get("normalized_text") or r.get("raw_message", "")
            if gt and str(gt).strip().lower() in ["normal", "suspicious"]:
                valid_pairs.append((txt, str(gt).strip().lower()))

        if len(valid_pairs) < 4:
            return {
                "evaluated": False,
                "status": "INSUFFICIENT_LABELED_DATA",
                "message": f"Found only {len(valid_pairs)} valid labeled records. Minimum 4 required for evaluation.",
            }

        texts = [p[0] for p in valid_pairs]
        y_true = [p[1] for p in valid_pairs]

        pred_results = ForensicModelInference.predict_batch(texts)
        y_pred = [p["predicted_label"] for p in pred_results]

        # Compute confusion matrix [[TN, FP], [FN, TP]] where normal=0, suspicious=1
        cm = confusion_matrix(y_true, y_pred, labels=["normal", "suspicious"])
        tn, fp, fn, tp = cm.ravel()

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, pos_label="suspicious", zero_division=0)
        rec = recall_score(y_true, y_pred, pos_label="suspicious", zero_division=0)
        f1 = f1_score(y_true, y_pred, pos_label="suspicious", zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # Detailed error audit
        false_positives = []
        false_negatives = []
        for i, (yt, yp, txt) in enumerate(zip(y_true, y_pred, texts)):
            if yt == "normal" and yp == "suspicious":
                false_positives.append({"index": i, "text": txt[:120], "score": pred_results[i]["score"]})
            elif yt == "suspicious" and yp == "normal":
                false_negatives.append({"index": i, "text": txt[:120], "score": pred_results[i]["score"]})

        result = {
            "evaluated": True,
            "status": "EVALUATED",
            "dataset_name": dataset_name,
            "sample_counts": {
                "total": len(valid_pairs),
                "normal": y_true.count("normal"),
                "suspicious": y_true.count("suspicious"),
            },
            "metrics": {
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "false_positive_rate": round(float(fpr), 4),
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn),
                "confusion_matrix": cm.tolist(),
            },
            "error_analysis": {
                "false_positives_count": len(false_positives),
                "false_negatives_count": len(false_negatives),
                "sample_false_positives": false_positives[:5],
                "sample_false_negatives": false_negatives[:5],
            }
        }

        if save_result:
            EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            with open(EVAL_SUMMARY_PATH, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

        return result
