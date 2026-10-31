"""
Email Feature Extraction Engine (URLs, Keywords, Structural Signals).
"""
import re, numpy as np
from typing import List, Dict, Any, Iterable
from sklearn.base import BaseEstimator, TransformerMixin

PHISHING_KEYWORDS = {"urgent", "immediately", "suspended", "verify", "kyc", "otp", "password", "locked", "unauthorized", "winner", "claim", "prize", "free", "overdue", "wire transfer", "bank account", "credit card"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".ru", ".tk", ".click", ".loan"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl"}

URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)

class EmailFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X: Iterable, y=None):
        return self

    @classmethod
    def analyze_single_email(cls, text: str, sender: str = "") -> Dict[str, Any]:
        combined = f"{sender} {text}".strip()
        lower_text = combined.lower()
        urls = URL_REGEX.findall(combined)
        url_count = len(urls)
        has_ip_url = 1 if IP_URL_REGEX.search(combined) else 0
        has_suspicious_tld = 1 if any(tld in lower_text for tld in SUSPICIOUS_TLDS) else 0
        has_url_shortener = 1 if any(s in lower_text for s in URL_SHORTENERS) else 0
        matched = [kw for kw in PHISHING_KEYWORDS if kw in lower_text]
        
        return {
            "urls_extracted": urls,
            "matched_keywords": sorted(matched),
            "url_count": url_count,
            "has_ip_url": bool(has_ip_url),
            "has_suspicious_tld": bool(has_suspicious_tld),
            "has_url_shortener": bool(has_url_shortener),
            "keyword_match_count": len(matched),
            "numeric_vector": [float(url_count), float(has_ip_url), float(has_suspicious_tld), float(has_url_shortener), float(len(matched)), float(len(combined))]
        }

    def transform(self, X: List[str]) -> np.ndarray:
        return np.array([self.analyze_single_email(doc)["numeric_vector"] for doc in X], dtype=np.float64)
