"""
model.py — Isolation Forest anomaly detection
Output: 0 = Normal, 1 = Suspicious
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")


def _generate_normal_data(n=1500) -> np.ndarray:
    np.random.seed(42)
    req = np.random.normal(loc=60, scale=25, size=n).clip(5, 150)
    logins = np.random.poisson(lam=1, size=n).clip(0, 5)
    return np.column_stack([req, logins])


def train_model():
    X = _generate_normal_data()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    model.fit(X_scaled)
    with open(MODEL_PATH, "wb") as f: pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f: pickle.dump(scaler, f)
    print("[Model] Trained and saved.")
    return model


def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        train_model()
    with open(MODEL_PATH, "rb") as f: model = pickle.load(f)
    with open(SCALER_PATH, "rb") as f: scaler = pickle.load(f)
    return model, scaler


def predict(features: list) -> list:
    if not features: return []
    model, scaler = load_model()
    X = np.array(features)
    X_s = scaler.transform(X)
    raw = model.predict(X_s)
    return [0 if p == 1 else 1 for p in raw]


def get_anomaly_scores(features: list) -> list:
    if not features: return []
    model, scaler = load_model()
    X = np.array(features)
    X_s = scaler.transform(X)
    return model.decision_function(X_s).tolist()


def classify_severity(requests: int, login_attempts: int, score: float) -> str:
    if login_attempts > 20 or requests > 400:
        return "HIGH"
    elif login_attempts > 10 or requests > 250 or score < -0.2:
        return "MEDIUM"
    return "LOW"
