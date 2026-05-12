# ⬡ Cyber Ultron v2 — Predictive Cyberattack Defence System

A full-stack cybersecurity dashboard with JWT authentication, AI anomaly detection, file upload, and real-time charts.

---

## 🔹 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
> If you get version errors, run: `pip install fastapi uvicorn scikit-learn numpy pandas python-multipart pydantic requests python-jose passlib bcrypt`

### 2. Start the backend (from project root)
```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Open in browser
```
http://localhost:8000
```

### 4. Login
- **Username:** `admin`
- **Password:** `admin123`

### 5. Run simulator (second terminal)
```bash
python scripts/simulate_logs.py --count 60 --attack-ratio 0.3
```

---

## 🔹 Features

| Feature | Description |
|---|---|
| JWT Login | Secure token-based authentication |
| Live Logs | Auto-refreshing table with source badges |
| AI Detection | Isolation Forest — click "Run Analysis" |
| File Upload | Upload JSON or CSV log files |
| Bar Chart | Requests per IP (Chart.js) |
| Pie Chart | Normal vs Suspicious ratio |
| Alerts Panel | Severity-coded threat cards |
| Auto-blocking | Anomalous IPs blocked automatically |
| Manual Block | Block any IP from the dashboard |

---

## 🔹 API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/login` | No | Get JWT token |
| POST | `/logs` | Yes | Add a log |
| GET | `/logs` | Yes | Get all logs |
| POST | `/detect` | Yes | Run AI detection |
| GET | `/alerts` | Yes | Get alerts |
| POST | `/block-ip` | Yes | Block an IP |
| GET | `/blocked` | Yes | Get blocked IPs |
| DELETE | `/blocked/{ip}` | Yes | Unblock an IP |
| POST | `/upload` | Yes | Upload JSON/CSV |
| GET | `/stats` | Yes | Dashboard stats |

---

## 🔹 Upload File Format

**JSON:**
```json
[
  {"ip": "10.0.0.1", "requests": 450, "login_attempts": 25, "timestamp": "2024-01-15T10:30:00"},
  {"ip": "192.168.1.5", "requests": 55, "login_attempts": 1, "timestamp": "2024-01-15T10:31:00"}
]
```

**CSV:**
```csv
ip,requests,login_attempts,timestamp
10.0.0.1,450,25,2024-01-15T10:30:00
192.168.1.5,55,1,2024-01-15T10:31:00
```

---

## 🔹 Project Structure

```
cyber-ultron/
├── backend/
│   ├── main.py       # FastAPI app + all endpoints
│   ├── auth.py       # JWT + bcrypt password hashing
│   ├── model.py      # Isolation Forest ML
│   ├── database.py   # SQLite setup (4 tables)
│   ├── schemas.py    # Pydantic models
│   └── utils.py      # Shared helpers
├── frontend/
│   ├── login.html    # Auth page
│   ├── dashboard.html# Main dashboard
│   ├── dashboard.js  # All frontend logic
│   └── styles.css    # Dark cyberpunk theme
├── scripts/
│   └── simulate_logs.py
├── data/             # SQLite DB stored here
├── requirements.txt
└── README.md
```

---

## 🔹 Troubleshooting

**"Cannot connect"** — Make sure backend is running in a separate terminal window that stays open.

**Install errors with scikit-learn** — Use: `pip install scikit-learn numpy --upgrade`

**passlib/jose errors** — Run: `pip install python-jose passlib bcrypt`

**Port in use** — Use a different port: `python -m uvicorn backend.main:app --port 8001`
