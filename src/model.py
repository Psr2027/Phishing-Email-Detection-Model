"""
Scikit-Learn Phishing Email Detection Pipeline.
"""
import os, joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from src.feature_extractor import EmailFeatureExtractor

class PhishingDetectionModel:
    def __init__(self):
        self.pipeline = Pipeline([
            ("features", FeatureUnion([
                ("tfidf", TfidfVectorizer(max_features=1500, stop_words="english")),
                ("structural", Pipeline([("ext", EmailFeatureExtractor()), ("scale", StandardScaler())]))
            ])),
            ("clf", RandomForestClassifier(n_estimators=100, random_state=42))
        ])
        self.metrics = {}

    def train_and_evaluate(self, csv_path: str, plot_path: str = "assets/confusion_matrix.png"):
        df = pd.read_csv(csv_path)
        X = [f"From: {s} | Subject: {sub} | Body: {b}" for s, sub, b in zip(df["sender"], df["subject"], df["body"])]
        y = df["label"].values

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
        self.pipeline.fit(X_train, y_train)
        y_pred = self.pipeline.predict(X_test)

        labels = ["Safe", "Phishing"]
        cm = confusion_matrix(y_test, y_pred, labels=labels)
        acc = accuracy_score(y_test, y_pred)
        cv = cross_val_score(self.pipeline, X, y, cv=5, scoring="accuracy").mean()

        self.metrics = {
            "total_samples": len(df),
            "accuracy": round(float(acc), 4),
            "cv_mean_accuracy": round(float(cv), 4),
            "confusion_matrix": cm.tolist()
        }

        os.makedirs(os.path.dirname(plot_path), exist_ok=True)
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.imshow(cm, cmap=plt.cm.Blues)
        ax.set(title=f"Confusion Matrix (Accuracy: {acc*100:.1f}%)", xticks=[0,1], yticks=[0,1], xticklabels=labels, yticklabels=labels, ylabel="Actual", xlabel="Predicted")
        plt.tight_layout()
        plt.savefig(plot_path)
        plt.close(fig)
        return self.metrics

    def predict_email(self, subject: str, body: str, sender: str = ""):
        doc = f"From: {sender} | Subject: {subject} | Body: {body}"
        pred = self.pipeline.predict([doc])[0]
        prob = self.pipeline.predict_proba([doc])[0]
        classes = list(self.pipeline.classes_)
        prob_map = {c: round(p*100, 2) for c, p in zip(classes, prob)}
        return {"prediction": str(pred), "confidence_percent": prob_map.get(str(pred), 0.0), "features": EmailFeatureExtractor.analyze_single_email(f"{subject} {body}", sender)}

    def save(self, path="models/phishing_detector.joblib"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "metrics": self.metrics}, path)

    @classmethod
    def load(cls, path="models/phishing_detector.joblib"):
        d = joblib.load(path)
        m = cls()
        m.pipeline = d["pipeline"]
        m.metrics = d.get("metrics", {})
        return m
