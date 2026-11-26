import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
import joblib
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    classification_report,
)

from config import (
    MODELS_DIR,
    RANDOM_SEED,
    MODEL_VERSION,
    CLASSIFIER_ESTIMATORS,
    TFIDF_NGRAM_RANGE,
    TFIDF_MAX_FEATURES,
    TFIDF_MIN_DF,
)
from src.ml.feature_extractor import build_tfidf_vectorizer
from src.preprocessing.text_cleaner import clean_log_text
from src.audit.audit_trail import AuditTrail

MODEL_PIPELINE_PATH = MODELS_DIR / "forensicshield_rf_pipeline.joblib"
MODEL_METADATA_PATH = MODELS_DIR / "model_metadata.json"

class ForensicModelTrainer:
    """
    Trains reproducible TF-IDF + Random Forest pipeline on verified labeled records.
    Strictly enforces separation between train and evaluation splits to prevent leakage.
    """

    @classmethod
    def train_binary_model(
        cls,
        texts: List[str],
        labels: List[str],  # "normal" or "suspicious"
        test_size: float = 0.25,
        provenance_source: str = "MANUAL_ANNOTATED_RECORDS",
        output_pipeline_path: Optional[Path] = None,
        output_metadata_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        if len(texts) < 10:
            raise ValueError(f"Insufficient samples for training ({len(texts)} samples). Need at least 10 samples.")

        # Ensure valid binary labels
        valid_labels = {"normal", "suspicious"}
        normalized_labels = []
        for l in labels:
            str_l = str(l).strip().lower()
            if str_l not in valid_labels:
                # Map alternate tags if present
                if str_l in ["benign", "clean", "0", "false"]:
                    normalized_labels.append("normal")
                else:
                    normalized_labels.append("suspicious")
            else:
                normalized_labels.append(str_l)

        # Check class representation
        unique_classes = set(normalized_labels)
        if len(unique_classes) < 2:
            raise ValueError(f"Training dataset must contain both classes. Found only: {unique_classes}")

        # Clean text uniformly
        cleaned_texts = [clean_log_text(t) for t in texts]

        # Split data before vectorization to prevent vocabulary leakage
        stratify = normalized_labels if min([normalized_labels.count(c) for c in unique_classes]) >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            cleaned_texts,
            normalized_labels,
            test_size=test_size,
            random_state=RANDOM_SEED,
            stratify=stratify,
        )

        vectorizer = build_tfidf_vectorizer(
            ngram_range=TFIDF_NGRAM_RANGE,
            max_features=TFIDF_MAX_FEATURES,
            min_df=TFIDF_MIN_DF if len(X_train) >= 100 else 1,
        )

        classifier = RandomForestClassifier(
            n_estimators=CLASSIFIER_ESTIMATORS,
            random_state=RANDOM_SEED,
            class_weight="balanced",
            max_depth=25,
            n_jobs=1,
        )

        # Build pipeline
        pipeline = Pipeline([
            ("tfidf", vectorizer),
            ("clf", classifier),
        ])

        # Fit strictly on train split
        pipeline.fit(X_train, y_train)

        # Evaluate on test split
        y_pred = pipeline.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, pos_label="suspicious", zero_division=0)
        rec = recall_score(y_test, y_pred, pos_label="suspicious", zero_division=0)
        f1 = f1_score(y_test, y_pred, pos_label="suspicious", zero_division=0)
        cm = confusion_matrix(y_test, y_pred, labels=["normal", "suspicious"]).tolist()

        save_pipeline = output_pipeline_path or MODEL_PIPELINE_PATH
        save_metadata = output_metadata_path or MODEL_METADATA_PATH

        # Save pipeline artifact
        save_pipeline.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, save_pipeline)

        # Compute SHA-256 of pipeline artifact
        hasher = hashlib.sha256()
        with open(save_pipeline, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        model_sha256 = hasher.hexdigest()

        # Vocabulary metadata
        vocab = vectorizer.vocabulary_
        metadata = {
            "model_version": MODEL_VERSION,
            "architecture": "TF-IDF + RandomForestClassifier",
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "pipeline_sha256": model_sha256,
            "total_samples": len(texts),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "classes": ["normal", "suspicious"],
            "vocabulary_size": len(vocab),
            "hyperparameters": {
                "n_estimators": CLASSIFIER_ESTIMATORS,
                "random_state": RANDOM_SEED,
                "class_weight": "balanced",
                "ngram_range": list(TFIDF_NGRAM_RANGE),
                "max_features": TFIDF_MAX_FEATURES,
            },
            "metrics": {
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "confusion_matrix": cm,
            },
            "provenance_source": provenance_source,
            "data_category": "SYNTHETIC_BENCHMARK" if "SYNTH" in provenance_source.upper() else "ANNOTATED_BENCHMARK",
        }

        with open(save_metadata, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        if output_pipeline_path is None:
            # Force reload in inference engine
            from src.ml.model_inference import ForensicModelInference
            ForensicModelInference.load_model(force_reload=True)

            # Record in audit trail
            AuditTrail.record_event(
                case_id="SYSTEM",
                actor="SYSTEM_TRAINER",
                action="MODEL_TRAINED",
                output_hash=model_sha256,
            )

        return metadata

    @classmethod
    def train_from_json_files(
        cls,
        train_path: Path,
        test_path: Path,
        provenance_source: str = "SYNTHETIC_BENCHMARK_CORPUS_v1.0",
        output_pipeline_path: Optional[Path] = None,
        output_metadata_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Trains and evaluates the primary TF-IDF + Random Forest model using structured JSON splits.
        Keeps train and test completely isolated. Fits TF-IDF solely on training records.
        """
        with open(train_path, "r", encoding="utf-8") as f:
            train_records = json.load(f)

        with open(test_path, "r", encoding="utf-8") as f:
            test_records = json.load(f)

        X_train = [clean_log_text(d.get("message", "") + " " + d.get("command_line", "")) for d in train_records]
        y_train = ["normal" if "benign" in d.get("labels", []) else "suspicious" for d in train_records]

        X_test = [clean_log_text(d.get("message", "") + " " + d.get("command_line", "")) for d in test_records]
        y_test = ["normal" if "benign" in d.get("labels", []) else "suspicious" for d in test_records]

        # Dataset quality and leakage validation
        if not X_train or not X_test:
            raise ValueError("Training or testing dataset is empty.")

        if any(not text for text in X_train + X_test):
            raise ValueError("Empty normalized text detected.")

        train_unique = set(X_train)
        test_unique = set(X_test)

        if len(train_unique) != len(X_train):
            raise ValueError("Duplicate training texts detected.")

        if len(test_unique) != len(X_test):
            raise ValueError("Duplicate testing texts detected.")

        overlap = train_unique & test_unique

        if overlap:
            raise ValueError(
                f"Data leakage detected: {len(overlap)} overlapping texts."
            )

        if set(y_train) != {"normal", "suspicious"}:
            raise ValueError("Training dataset must contain both classes.")

        if set(y_test) != {"normal", "suspicious"}:
            raise ValueError("Testing dataset must contain both classes.")

        print("Dataset quality validation passed.")
        print(f"Unique training texts: {len(train_unique)}")
        print(f"Unique testing texts: {len(test_unique)}")
        print(f"Train-Test overlap: {len(overlap)}")

        vectorizer = build_tfidf_vectorizer(
            ngram_range=TFIDF_NGRAM_RANGE,
            max_features=TFIDF_MAX_FEATURES,
            min_df=TFIDF_MIN_DF,
        )

        # Fit strictly on train split
        vectorizer.fit(X_train)

        X_train_vec = vectorizer.transform(X_train)
        X_test_vec = vectorizer.transform(X_test)

        classifier = RandomForestClassifier(
            n_estimators=CLASSIFIER_ESTIMATORS,
            random_state=RANDOM_SEED,
            class_weight="balanced",
            max_depth=25,
            n_jobs=-1,
        )
        classifier.fit(X_train_vec, y_train)

        pipeline = Pipeline([
            ("tfidf", vectorizer),
            ("clf", classifier),
        ])

        y_pred = classifier.predict(X_test_vec)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, pos_label="suspicious", zero_division=0)
        rec = recall_score(y_test, y_pred, pos_label="suspicious", zero_division=0)
        f1 = f1_score(y_test, y_pred, pos_label="suspicious", zero_division=0)
        cm = confusion_matrix(y_test, y_pred, labels=["normal", "suspicious"]).tolist()

        save_pipeline = output_pipeline_path or MODEL_PIPELINE_PATH
        save_metadata = output_metadata_path or MODEL_METADATA_PATH

        save_pipeline.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, save_pipeline)

        hasher = hashlib.sha256()
        with open(save_pipeline, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        model_sha256 = hasher.hexdigest()

        metadata = {
            "model_version": MODEL_VERSION,
            "architecture": "TF-IDF + RandomForestClassifier",
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "pipeline_sha256": model_sha256,
            "total_samples": len(train_records) + len(test_records),
            "train_samples": len(train_records),
            "test_samples": len(test_records),
            "classes": ["normal", "suspicious"],
            "vocabulary_size": len(vectorizer.vocabulary_),
            "hyperparameters": {
                "n_estimators": CLASSIFIER_ESTIMATORS,
                "random_state": RANDOM_SEED,
                "class_weight": "balanced",
                "ngram_range": list(TFIDF_NGRAM_RANGE),
                "max_features": TFIDF_MAX_FEATURES,
                "min_df": TFIDF_MIN_DF,
            },
            "metrics": {
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "confusion_matrix": cm,
            },
            "provenance_source": provenance_source,
            "data_category": "SYNTHETIC_BENCHMARK_CORPUS",
            "evaluation_notice": (
                f"Metrics evaluated on {len(test_records):,} held-out synthetic test records. "
                "External dataset files are present, but their authenticity and independent validation remain unverified. "
                "Synthetic benchmark metrics must not be interpreted as real-world performance. "
                "Similar-template leakage has not yet been ruled out."
            )
        }

        with open(save_metadata, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        if output_pipeline_path is None:
            from src.ml.model_inference import ForensicModelInference
            ForensicModelInference.load_model(force_reload=True)

            AuditTrail.record_event(
                case_id="SYSTEM",
                actor="SYSTEM_TRAINER",
                action="MODEL_TRAINED_BENCHMARK_CORPUS",
                output_hash=model_sha256,
            )

        return metadata

