"""
simulate_logs.py — Cyber Ultron v2 Log Simulator
Sends normal + attack-pattern logs to the backend (requires login).

Usage:
    python scripts/simulate_logs.py [--url URL] [--count N] [--attack-ratio R] [--continuous]
    python scripts/simulate_logs.py --user admin --password admin123
"""
import argparse
import random
import time
import requests
from datetime import datetime, timezone, timedelta

DEFAULT_URL = "http://localhost:8000"

NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 80)]
ATTACK_IPS = [
    "10.0.0.1","10.0.0.2","172.16.0.5",
    "185.220.101.1","45.33.32.156","198.51.100.9",
    "203.0.113.42","198.18.0.1","91.108.4.33","46.229.168.1"
]


def utc_now(offset=0):
    d = datetime.now(timezone.utc) - timedelta(minutes=offset)
    return d.strftime("%Y-%m-%dT%H:%M:%S")


def normal_log():
    return {"ip": random.choice(NORMAL_IPS), "requests": random.randint(10,150),
            "login_attempts": random.randint(0,3), "timestamp": utc_now(random.randint(0,10)), "source": "simulated"}


def attack_log():
    t = random.choice(["ddos","brute","combined"])
    if t == "ddos":
        return {"ip": random.choice(ATTACK_IPS), "requests": random.randint(300,600), "login_attempts": random.randint(0,5), "timestamp": utc_now(), "source": "simulated"}
    elif t == "brute":
        return {"ip": random.choice(ATTACK_IPS), "requests": random.randint(20,100), "login_attempts": random.randint(15,50), "timestamp": utc_now(), "source": "simulated"}
    else:
        return {"ip": random.choice(ATTACK_IPS), "requests": random.randint(250,500), "login_attempts": random.randint(10,40), "timestamp": utc_now(), "source": "simulated"}


def get_token(url, username, password):
    try:
        r = requests.post(f"{url}/login", json={"username": username, "password": password}, timeout=5)
        if r.status_code == 200:
            return r.json()["access_token"]
        print(f"[Auth] Login failed: {r.json().get('detail','Unknown error')}")
    except Exception as e:
        print(f"[Auth] Cannot connect: {e}")
    return None


def send_log(url, token, log):
    try:
        r = requests.post(f"{url}/logs", json=log,
                          headers={"Authorization": f"Bearer {token}"}, timeout=5)
        return r.status_code == 200
    except:
        return False


def run_detect(url, token):
    try:
        r = requests.post(f"{url}/detect",
                          headers={"Authorization": f"Bearer {token}"}, timeout=15)
        return r.json() if r.status_code == 200 else None
    except:
        return None


def main():
    p = argparse.ArgumentParser(description="Cyber Ultron v2 Log Simulator")
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin123")
    p.add_argument("--count", type=int, default=50)
    p.add_argument("--attack-ratio", type=float, default=0.25)
    p.add_argument("--delay", type=float, default=0.08)
    p.add_argument("--continuous", action="store_true")
    args = p.parse_args()

    print("=" * 60)
    print("  CYBER ULTRON v2 — Log Simulator")
    print("=" * 60)
    print(f"  URL     : {args.url}")
    print(f"  Count   : {args.count} logs/batch")
    print(f"  Attacks : {int(args.attack_ratio*100)}%")
    print("=" * 60)

    print(f"\n[Auth] Logging in as '{args.user}'...")
    token = get_token(args.url, args.user, args.password)
    if not token:
        print("[Auth] Failed to get token. Is the backend running?")
        return
    print("[Auth] Token acquired ✓\n")

    batch = 0
    while True:
        batch += 1
        n_attack = int(args.count * args.attack_ratio)
        n_normal = args.count - n_attack
        logs = [normal_log() for _ in range(n_normal)] + [attack_log() for _ in range(n_attack)]
        random.shuffle(logs)

        print(f"[Batch {batch}] {n_normal} normal + {n_attack} attack logs...")
        ok = 0
        for i, log in enumerate(logs, 1):
            label = "ATTACK" if log["requests"] > 200 or log["login_attempts"] > 10 else "normal"
            if send_log(args.url, token, log):
                ok += 1
                print(f"  [{i:03d}] {log['ip']:18s} req={log['requests']:4d} logins={log['login_attempts']:3d} [{label}] ✓")
            else:
                print(f"  [{i:03d}] FAILED — is backend running?")
                break
            if args.delay > 0:
                time.sleep(args.delay)

        print(f"\n  Sent {ok}/{len(logs)} logs")

        if ok > 0:
            print("  Running detection...")
            r = run_detect(args.url, token)
            if r:
                print(f"  ✓ Analyzed: {r['total_logs_analyzed']} | ⚠ Anomalies: {r['anomalies_detected']} | 🚫 Blocked: {r['blocked_ips_added']}")

        if not args.continuous:
            break
        print("\n[Waiting 10s...]\n")
        time.sleep(10)

    print("\n[Done]")


if __name__ == "__main__":
    main()
