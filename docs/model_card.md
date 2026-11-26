# ForensicShield AI: Model Card
**Model Identifier:** `fs-rf-v1.0`  
**Pipeline Architecture:** Sublinear TF-IDF (N-Grams 1–2) + Balanced Random Forest Classifier  
**Project Reference:** Project 218 — Anti-Forensic Technique Detection via Natural Language Processing for Forensic Text/Log Analysis  

---

## 1. Model Overview & Purpose

- **Task Type:** Binary Classification (`normal` vs `suspicious`) with continuous evasion score $P(\text{suspicious})$.
- **Core Research Problem:** Detection of post-attack anti-forensic maneuvers (event log tampering, shadow copy deletion, security tool disabling, bash history clearing, and timestomping) within forensic text/log records.
- **Role in Investigation:** Triage and prioritization aid for human forensic investigators during post-incident ransomware analysis.

> [!IMPORTANT]
> A classification of `suspicious` is an investigative alert indicating that the event warrants human analyst review. It does not establish malicious actor intent, judicial guilt, or legal liability without independent corroboration.

---

## 2. Feature Extraction & Model Architecture

| Component | Technical Specification | Rationale |
|---|---|---|
| **Preprocessor** | Text cleaner preserving command switches, hex, and paths | Retains critical switches (`-enc`, `/all`, `/quiet`, `-r`, `vssadmin`) while normalizing non-semantic noise. |
| **Vectorization** | `TfidfVectorizer(ngram_range=(1,2), max_features=5000, sublinear_tf=True)` | Captures single keywords and composite command bigrams (`delete shadows`, `cl security`, `stop auditd`). |
| **Classifier** | `RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)` | Robust ensemble resilient to noisy text logs, with natural compatibility with `shap.TreeExplainer`. |
| **Leakage Control** | Vectorizer fitted strictly on training split only | Held-out test records never influence feature vocabulary or document frequencies. |

---

## 3. Explainability (XAI) with SHAP

- **Method:** `shap.TreeExplainer` on the fitted tree ensemble.
- **Attribution Mapping:** Inverse-mapped from active feature indices back to specific token bigrams in the vocabulary.
- **Output:** Directional impact (positive pushes towards `suspicious`, negative counterbalances towards `normal`), localized contribution scores, and plain-English investigative summaries.
- **Mandatory Caveat:**
  *"SHAP attribution identifies statistical token contributions for this model prediction. It does not establish attacker intent, causation, or legal guilt."*

---

## 4. Heuristic Rules vs Learned Machine Learning

To maintain forensic transparency, the application separates **explicit heuristic rules** from **statistical machine learning predictions**:
1. **Rule Engine:** Matches 8 deterministic signatures aligned with the *Anti-Forensics SoK (2026)* taxonomy (e.g., `wevtutil cl`, `vssadmin delete shadows`, `Set-MpPreference -DisableRealtimeMonitoring`).
2. **ML Model:** Generalizes across variations, unrecognized flags, and novel combinations.
3. **Derived Tagging:** The UI distinctly flags events as `RULE`, `ML`, or `RULE+ML`.

---

## 5. Technical Limitations & Risks

1. **Semantic & Sequence Limits:** TF-IDF represents bag-of-tokens and lacks temporal state awareness across multiple consecutive events.
2. **Zero-Feature Fallback:** Out-of-vocabulary logs containing zero known keywords safely default to `normal` (0.0 score) rather than arbitrary tree fall-through.
3. **CTF vs Enterprise Generalization:** Models evaluated on synthetic or CTF challenge artifacts cannot be assumed to generalize directly to noisy corporate SIEM environments without domain fine-tuning.
