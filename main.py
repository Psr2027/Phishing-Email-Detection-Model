#!/usr/bin/env python3
"""Phishing Email Detection CLI"""
import os, sys
from src.dataset_generator import save_dataset_csv
from src.model import PhishingDetectionModel

DATASET = os.path.join("data", "emails_dataset.csv")
MODEL = os.path.join("models", "phishing_detector.joblib")

def ensure_model():
    if not os.path.exists(DATASET):
        save_dataset_csv(DATASET, 500)
    if os.path.exists(MODEL):
        return PhishingDetectionModel.load(MODEL)
    m = PhishingDetectionModel()
    m.train_and_evaluate(DATASET)
    m.save(MODEL)
    return m

if __name__ == "__main__":
    m = ensure_model()
    print("Model loaded & ready! Accuracy:", m.metrics.get("accuracy"))
