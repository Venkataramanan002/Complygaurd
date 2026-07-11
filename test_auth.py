"""Quick auth test script."""
import os

import requests
from dotenv import load_dotenv

load_dotenv()
BASE = f"http://localhost:{os.getenv('PORT', '8000')}"
ADMIN_PASSWORD = os.environ["DEFAULT_ADMIN_PASSWORD"]  # from .env — never hardcode

# Test 1: Admin login
print("=== Test 1: Admin Login ===")
r = requests.post(f"{BASE}/api/auth/login", json={
    "username": "admin",
    "password": ADMIN_PASSWORD
})
print(f"Status: {r.status_code}")
print(f"Body: {r.text[:300]}")

token = None
if r.status_code == 200:
    token = r.json()["access_token"]
    print(f"Token: {token[:30]}...")

# Test 2: /me with token
print("\n=== Test 2: /me with token ===")
headers = {"Authorization": f"Bearer {token}"} if token else {}
r2 = requests.get(f"{BASE}/api/auth/me", headers=headers)
print(f"Status: {r2.status_code}")
print(f"Body: {r2.text[:300]}")

# Test 3: Register without a token is rejected
print("\n=== Test 3: Register without token (expect 401/403) ===")
r3 = requests.post(f"{BASE}/api/auth/register", json={
    "username": "hacker22",
    "email": "h@h.com",
    "password": "GoodPass1A!",
    "role": "admin"
})
print(f"Status: {r3.status_code}")
print(f"Body: {r3.text[:300]}")

# Test 4: Weak password rejected (as admin)
print("\n=== Test 4: Weak password ===")
r4 = requests.post(f"{BASE}/api/auth/register", json={
    "username": "testuser",
    "email": "t@t.com",
    "password": "weak",
    "role": "viewer"
}, headers=headers)
print(f"Status: {r4.status_code}")
print(f"Body: {r4.text[:200]}")

# Test 5: Security headers present (and anonymous /me rejected)
print("\n=== Test 5: Security Headers ===")
r5 = requests.get(f"{BASE}/api/auth/me")
print(f"Status without token: {r5.status_code} (expect 401)")
for h in ["x-content-type-options", "x-frame-options", "x-request-id"]:
    print(f"  {h}: {r5.headers.get(h, 'MISSING')}")

# Test 6: Duplicate registration blocked (as admin)
print("\n=== Test 6: Duplicate registration ===")
r6 = requests.post(f"{BASE}/api/auth/register", json={
    "username": "hacker22",
    "email": "h2@h.com",
    "password": "GoodPass1A!",
    "role": "viewer"
}, headers=headers)
print(f"Status: {r6.status_code}")
print(f"Body: {r6.text[:200]}")

print("\n=== DONE ===")
