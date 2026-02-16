#!/usr/bin/env python3
"""Test script to identify which header triggers cache_poisoning"""

import requests
import json

BASE_URL = "http://localhost:8000"

# Test headers one by one
headers_to_test = [
    ("X-Forwarded-Host", "secure.idts.dpc.com.tn"),
    ("X-Forwarded-For", "192.168.37.1"),
    ("X-Forwarded-Proto", "https"),
    ("X-Forwarded-Scheme", "https"),
    ("X-Real-IP", "192.168.37.1"),
    ("X-Scheme", "https"),
    ("X-Request-ID", "abc123"),
    ("X-Original-Forwarded-For", "10.0.0.1"),
    ("Forwarded", "for=192.168.37.1;proto=https;host=secure.idts.dpc.com.tn"),
    ("X-Forwarded-Port", "443"),
    ("X-Forwarded-Prefix", "/api"),
]

print("Testing headers one by one...")
for header_name, header_value in headers_to_test:
    try:
        resp = requests.get(f"{BASE_URL}/api/orders", headers={header_name: header_value}, timeout=5)
        status = "BLOCKED" if resp.status_code == 403 and "blocked" in resp.text else "OK"
        print(f"  {header_name}: {header_value} -> {status} ({resp.status_code})")
    except Exception as e:
        print(f"  {header_name}: {header_value} -> ERROR: {e}")

print("\nTesting combinations...")
# Test combinations that Nginx Ingress might send
combinations = [
    {"X-Forwarded-Host": "secure.idts.dpc.com.tn", "X-Forwarded-For": "192.168.37.1"},
    {"X-Forwarded-Host": "secure.idts.dpc.com.tn", "X-Forwarded-Proto": "https"},
    {"X-Forwarded-For": "192.168.37.1", "X-Forwarded-Proto": "https"},
    {"X-Forwarded-Host": "secure.idts.dpc.com.tn", "X-Forwarded-For": "192.168.37.1", "X-Forwarded-Proto": "https"},
    {"X-Forwarded-Scheme": "https", "X-Scheme": "https"},
    {"X-Forwarded-Port": "443", "X-Forwarded-Proto": "https"},
]

for i, headers in enumerate(combinations):
    try:
        resp = requests.get(f"{BASE_URL}/api/orders", headers=headers, timeout=5)
        status = "BLOCKED" if resp.status_code == 403 and "blocked" in resp.text else "OK"
        print(f"  Combination {i+1}: {status} ({resp.status_code})")
        if status == "BLOCKED":
            print(f"    Headers: {headers}")
            print(f"    Response: {resp.text[:200]}")
    except Exception as e:
        print(f"  Combination {i+1}: ERROR: {e}")

print("\nTesting all headers together (like Nginx Ingress)...")
all_headers = {
    "X-Forwarded-Host": "secure.idts.dpc.com.tn",
    "X-Forwarded-For": "192.168.37.1",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Scheme": "https",
    "X-Real-IP": "192.168.37.1",
    "X-Scheme": "https",
    "X-Forwarded-Port": "443",
}
try:
    resp = requests.get(f"{BASE_URL}/api/orders", headers=all_headers, timeout=5)
    status = "BLOCKED" if resp.status_code == 403 and "blocked" in resp.text else "OK"
    print(f"  All headers: {status} ({resp.status_code})")
    if status == "BLOCKED":
        print(f"  Response: {resp.text[:200]}")
except Exception as e:
    print(f"  All headers: ERROR: {e}")
