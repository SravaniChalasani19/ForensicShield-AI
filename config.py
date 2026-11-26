import os
from pathlib import Path

# Project 218: ForensicShield AI Authoritative Configuration
APP_NAME = "ForensicShield AI"
APP_SUBTITLE = "NLP-Based Anti-forensic Investigation for Ransomware Incident Response"
SYSTEM_VERSION = "1.0.0"
MODEL_VERSION = "fs-rf-v1.0"
RANDOM_SEED = 42

BASE_DIR = Path(__file__).resolve().parent

# Check for Serverless / Cloud Environment (e.g., Vercel, AWS Lambda)
IS_SERVERLESS = os.environ.get("VERCEL") == "1" or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None

# Storage Directories (Use /tmp on serverless environments where root filesystem is read-only)
if IS_SERVERLESS:
    TMP_ROOT = Path("/tmp/forensicshield")
    DATA_DIR = TMP_ROOT / "data"
    REPORTS_DIR = TMP_ROOT / "reports"
    ORIGINALS_DIR = DATA_DIR / "originals"
    DERIVED_DIR = DATA_DIR / "derived"
    MANIFESTS_DIR = DATA_DIR / "manifests"
    DB_PATH = DATA_DIR / "forensicshield.db"
else:
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = BASE_DIR / "reports"
    ORIGINALS_DIR = DATA_DIR / "originals"
    DERIVED_DIR = DATA_DIR / "derived"
    MANIFESTS_DIR = DATA_DIR / "manifests"
    DB_PATH = DATA_DIR / "forensicshield.db"

# Static fixtures and model files are always bundled inside the project repository (read-only)
FIXTURES_DIR = BASE_DIR / "data" / "fixtures"
SYNTHETIC_DATA_DIR = BASE_DIR / "data" / "synthetic"
EXTERNAL_DATA_DIR = BASE_DIR / "data" / "external"
MODELS_DIR = BASE_DIR / "models"

# Persistent Cloud Database (e.g. Neon, Supabase, Vercel Postgres)
DATABASE_URL = os.environ.get("DATABASE_URL")

# Safe directory creation (catches read-only filesystem exceptions on serverless)
for folder in [DATA_DIR, ORIGINALS_DIR, DERIVED_DIR, MANIFESTS_DIR, REPORTS_DIR]:
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

# Upload, Security, and Resource Constraints
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
MAX_CASES_PER_USER = 15
MAX_EVIDENCE_PER_CASE = 10
MAX_REPORTS_PER_CASE = 10

ALLOWED_EXTENSIONS = {".csv", ".txt", ".log", ".json", ".jsonl", ".evtx"}
DISALLOWED_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".py", ".dll", ".so", ".bin", ".elf"}

# NLP & Model Hyperparameters
TFIDF_NGRAM_RANGE = (1, 2)
TFIDF_MAX_FEATURES = 5000
TFIDF_MIN_DF = 2
CLASSIFIER_ESTIMATORS = 100
CONFIDENCE_THRESHOLD = 0.50

# Technique Taxonomy (Anti-Forensics SoK 2026 Reference)
TARGET_TECHNIQUES = [
    "event_log_clearing",
    "backup_deletion",
    "security_tool_tampering",
    "timestamp_manipulation",
    "evidence_removal",
    "history_clearing",
    "command_obfuscation",
]

# Legal & Scientific Integrity Disclaimer
LEGAL_DISCLAIMER = (
    "The findings support investigator review. Legal admissibility depends on "
    "applicable law, evidence handling, chain-of-custody procedures and judicial evaluation."
)

# Literature Survey Traceability (Project 218 Official References from Academic PDFs)
LITERATURE_SURVEY_MAPPING = {
    1: {
        "paper": "A Sysmon Incremental Learning System for Ransomware Analysis and Detection (SILRAD, 2025)",
        "authors": "Jamil Ispahany, MD Rafiqul Islam, M. Arif Khan, MD Zahidul Islam",
        "institution": "Charles Sturt University & Cyber Security Cooperative Research Centre, Australia",
        "contribution": "Sysmon-based ransomware telemetry analysis and multi-stage classification rationale."
    },
    2: {
        "paper": "NLP-Based .NET CLR Event Logs Analyzer (2025)",
        "authors": "Maxim Stavtsev, Sergey Shershakov",
        "institution": "HSE University, Moscow, Russia",
        "contribution": "NLP tokenization and anomaly analysis rationale for forensic event logs."
    },
    3: {
        "paper": "Explainable Artificial Intelligence (XAI) for Malware Analysis: A Survey of Techniques, Applications, and Open Challenges (IEEE Access, 2025)",
        "authors": "Harikha Manthena, Shaghayegh Shajarian, Jeffrey Kimmell, Mahmoud Abdelsalam, Sajad Khorsandroo, Maanak Gupta",
        "institution": "North Carolina A&T State University & Tennessee Tech University, USA",
        "contribution": "Research justification for Explainable AI (SHAP) token attributions and legal/scientific attribution caveats."
    },
    4: {
        "paper": "SoK: Understanding Anti-Forensics Concepts and Research Practices Across Forensic Subdomains (2026)",
        "authors": "Janine Schneider, Florian Ramming, Maximilian Eichhorn, Gaston Pugliese, Chris Hargreaves, Jan Gruber, Joschua Schilling, Julian Geus, Kevin Mayer, Lea Uhlenbrock, Lena Voigt, Frank Breitinger",
        "institution": "University of Augsburg, FAU Erlangen-Nürnberg, Oxford University, KIT, CISPA",
        "contribution": "Systematic taxonomy, definitions, and categorization for anti-forensic indicators and event manipulation."
    },
    5: {
        "paper": "Network Intrusion Forensic Detection System with Explainable Artificial Intelligence and Digital Chain of Custody (2026)",
        "authors": "José Luis Vela, Carmen Pellicer",
        "institution": "CESTE, University Center, Zaragoza, Spain",
        "contribution": "Motivates evidence integrity verification (SHA-256), model traceability, and append-only audit chaining."
    },
    6: {
        "paper": "DEEPCASE: Semi-Supervised Contextual Analysis of Security Events (IEEE S&P / 2022)",
        "authors": "Thijs van Ede, Hojjat Aghakhani, Noah Spahn, Riccardo Bortolameotti, Marco Cova, Andrea Continella, Maarten van Steen, Andreas Peter, Christopher Kruegel, Giovanni Vigna",
        "institution": "University of Twente, UC Santa Barbara, ReaQta, VMware",
        "contribution": "Motivates temporal proximity analysis and contextual review of related security events."
    },
    7: {
        "paper": "LogBERT: Log Anomaly Detection via BERT (IJCNN 2021)",
        "authors": "Haixuan Guo, Shuhan Yuan, Xintao Wu",
        "institution": "Utah State University & University of Arkansas, USA",
        "contribution": "Contextual log anomaly analysis benchmark; background for NLP feature extraction baseline."
    },
    8: {
        "paper": "Digital forensic of Maze ransomware: A case of electricity distributor enterprise in ASEAN (Expert Systems with Applications 249, 2024)",
        "authors": "Krishna Chimmanee, Suttisak Jantavongso",
        "institution": "Rangsit University, Pathumthani, Thailand",
        "contribution": "Real-world ransomware post-attack investigative context, shadow copy deletion, and enterprise case-study motivation."
    }
}

# Approved Research Gaps & Proposed Improvements (Project 218 Academic Documentation)
APPROVED_RESEARCH_GAPS = [
    {
        "gap_id": 1,
        "title": "Manual Forensic Log Analysis",
        "limitation": "Manual examination of large forensic log datasets is time-consuming. Existing ransomware forensic investigations, such as the Maze ransomware case study, involve detailed examination of digital evidence.",
        "improvement": "Use NLP and machine learning to automatically identify suspicious forensic log records for investigator review."
    },
    {
        "gap_id": 2,
        "title": "Limited Anti-forensic Technique Classification",
        "limitation": "Existing research, including SILRAD and LogBERT, focuses on ransomware detection or general log anomaly detection rather than specifically identifying anti-forensic techniques. The Anti-Forensics SoK study provides a systematic understanding of anti-forensic techniques but does not implement the proposed NLP-based detection system.",
        "improvement": "Develop a classification approach focused on suspicious evidence-hiding, log-tampering, and evidence-manipulation indicators."
    },
    {
        "gap_id": 3,
        "title": "Limitations of Keyword-based and General Anomaly Detection",
        "limitation": "Fixed keyword and signature-based methods may fail to recognize variations in suspicious log entries. NLP-Based .NET CLR Event Logs Analyzer and LogBERT demonstrate advanced log analysis, but they do not specifically classify ransomware-related anti-forensic techniques.",
        "improvement": "Combine TF-IDF-based NLP features with machine learning classification and evaluate detection performance against rule-based baselines."
    },
    {
        "gap_id": 4,
        "title": "Limited Explainability",
        "limitation": "Some machine learning models provide predictions without sufficient explanations. The XAI for Malware Analysis survey highlights the importance of interpretable results in cybersecurity investigations.",
        "improvement": "Integrate SHAP to explain the features contributing to suspicious classifications and support investigator understanding."
    },
    {
        "gap_id": 5,
        "title": "Limited Investigation Context",
        "limitation": "Individual log entries may not provide enough information to reconstruct suspicious activities. DeepCASE demonstrates the importance of analyzing related security events, while the Maze ransomware study highlights the value of incident-specific forensic investigation.",
        "improvement": "Include available timestamps, related events, and ransomware investigation context in forensic analysis."
    },
    {
        "gap_id": 6,
        "title": "Evidence Integrity and Traceability",
        "limitation": "Automated classification results alone do not establish reliable evidence handling. The Network Intrusion Forensic Detection System with XAI and Digital Chain of Custody demonstrates the importance of evidence integrity and traceable forensic processing.",
        "improvement": "Include SHA-256 hashing, evidence references, processing records, and audit information in the reporting workflow."
    },
    {
        "gap_id": 7,
        "title": "Dataset Generalization",
        "limitation": "Models evaluated on limited datasets may perform poorly in different forensic environments. Existing studies use different log sources, datasets, and investigation scenarios, which may limit direct generalization.",
        "improvement": "Evaluate the proposed framework on suitable DFRWS and HackTheBox forensic datasets, where compatible evidence is available, and document dataset-specific performance."
    }
]

REMAINING_PROJECT_LIMITATIONS = [
    "Detection accuracy depends on the quality and availability of forensic logs.",
    "Reliable labeled anti-forensic datasets may be limited.",
    "TF-IDF may not capture complex semantic and temporal relationships.",
    "Machine learning predictions may contain false positives and false negatives.",
    "SHAP explanations do not independently prove that a prediction is correct.",
    "SHA-256 hashing alone does not establish complete legal chain of custody.",
    "Court admissibility depends on applicable legal requirements and forensic procedures.",
    "Performance on CTF-style datasets may not fully represent real-world ransomware investigations."
]
