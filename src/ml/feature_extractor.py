from sklearn.feature_extraction.text import TfidfVectorizer
from config import TFIDF_NGRAM_RANGE, TFIDF_MAX_FEATURES, TFIDF_MIN_DF

def build_tfidf_vectorizer(
    ngram_range=TFIDF_NGRAM_RANGE,
    max_features=TFIDF_MAX_FEATURES,
    min_df=TFIDF_MIN_DF,
) -> TfidfVectorizer:
    """
    Constructs a TF-IDF vectorizer tailored for forensic commands and log text.
    The custom token pattern preserves switches, dots, and hyphens (e.g., -enc, .exe, vssadmin).
    """
    return TfidfVectorizer(
        ngram_range=ngram_range,
        max_features=max_features,
        min_df=min_df,
        token_pattern=r'(?u)\b[\w\.\-]{2,}\b',
        sublinear_tf=True,
    )
