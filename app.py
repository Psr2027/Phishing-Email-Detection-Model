"""Flask Web UI"""
from flask import Flask, request, jsonify, render_template_string
from main import ensure_model

app = Flask(__name__)
model = ensure_model()

@app.route("/")
def index():
    return render_template_string("<h1>Phishing Email Detector</h1><p>Model Accuracy: {{ acc }}%</p>", acc=model.metrics.get("accuracy", 0)*100)

if __name__ == "__main__":
    app.run(port=5000)
