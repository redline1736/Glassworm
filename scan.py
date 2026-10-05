# csrf_scanner.py
"""
CSRF scanner — combines static code review and dynamic request testing.

Usage:
    python csrf_scanner.py --url http://localhost:5000/transfer \
                           --cookie "session=<sid>" \
                           --method POST \
                           --data "to=bob&amount=1"

    python csrf_scanner.py --source vulnerable_app.py
"""

import argparse, re, sys, requests
from urllib.parse import urlparse



# ---------------------------------------------------------------
# PART A: STATIC ANALYSIS
# ---------------------------------------------------------------

# Patterns that suggest a state-changing route exists
ROUTE_PATTERN = re.compile(
    r"@\w+\.route\(\s*['\"]([^'\"]+)['\"]"      # path
    r"(?:[^)]*methods\s*=\s*\[([^\]]*)\])?",     # optional methods list
    re.IGNORECASE,
)

# Signs that a route IS protected
CSRF_PROTECTED_HINTS = [
    r"csrf_token",              # form field name
    r"X-CSRF-Token",            # header name
    r"csrf_protect",            # Django decorator
    r"verify_csrf",             # generic
    r"CSRFProtect",             # Flask-WTF init
    r"csurf",                   # Express equivalent
    r"@csrf_protect",
]

# Signs the developer EXPLICITLY disabled protection
CSRF_DISABLED_HINTS = [
    r"@csrf_exempt",
    r"csrf\s*=\s*False",
    r"WTF_CSRF_ENABLED\s*=\s*False",
]


def static_scan(path: str):
    """Scan a Python/JS source file for missing CSRF protections."""
    print(f"\n[*] Static scan: {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()

    findings = []

    # 1. Explicit bypasses
    for pat in CSRF_DISABLED_HINTS:
        for m in re.finditer(pat, src, re.IGNORECASE):
            line = src[:m.start()].count("\n") + 1
            findings.append(("HIGH", line, f"CSRF protection explicitly disabled: {pat}"))

    # 2. State-changing routes with no visible token handling nearby
    for m in ROUTE_PATTERN.finditer(src):
        route_path = m.group(1)
        methods = (m.group(2) or "'GET'").upper()

        # Only care about state-changing verbs
        if not any(v in methods for v in ("POST", "PUT", "PATCH", "DELETE")):
            continue

        # Slice out the function body (next ~40 lines is a heuristic)
        start = m.end()
        body = src[start:start + 4000]

        # Check if ANY protection hint is present in this function
        has_protection = any(re.search(h, body, re.IGNORECASE)
                             for h in CSRF_PROTECTED_HINTS)

        # Check that auth exists at all
        has_auth = re.search(r"session|current_user|cookie|Authorization",
                             body, re.IGNORECASE)

        line = src[:m.start()].count("\n") + 1

        if has_auth and not has_protection:
            findings.append(("HIGH", line,
                f"State-changing route '{route_path}' [{methods}] uses session auth "
                f"but no CSRF token check detected"))
        elif has_auth and has_protection:
            findings.append(("INFO", line,
                f"Route '{route_path}' appears to check a CSRF token"))

    # Report
    if not findings:
        print("    No issues found.")
    else:
        for sev, line, msg in sorted(findings, key=lambda x: -len(x[0])):
            print(f"    [{sev}] line {line}: {msg}")
    return findings


# ---------------------------------------------------------------
# PART B: DYNAMIC ANALYSIS
# ---------------------------------------------------------------

def dynamic_scan(url, method, cookie, data, extra_headers=None):
    """
    Send a state-changing request WITHOUT any CSRF token.
    If the server accepts it, CSRF protection is likely absent.
    """
    print(f"\n[*] Dynamic scan: {method} {url}")
    if extra_headers:
        print(f"    Extra headers: {extra_headers}")
    else:
        print(f"    Cookie: {cookie}")

    headers = {"Cookie": cookie} if cookie else {}
    headers.update(extra_headers or {})

    # A real browser sends Origin/Referer on cross-site requests.
    # We can simulate what happens when they're absent OR when Origin
    # is an attacker-controlled domain — both test CSRF defenses.
    tests = [
        ("no Origin/Referer",
         {k: v for k, v in headers.items()
          if k.lower() not in ("origin", "referer")}),
        ("evil Origin",
         {**headers, "Origin": "https://evil.example"}),
        ("evil Referer",
         {**headers, "Referer": "https://evil.example/attack.html"}),
    ]

    results = []
    for label, hdrs in tests:
        try:
            if method.upper() == "POST":
                r = requests.post(url, headers=hdrs, data=data, timeout=10)
            elif method.upper() == "PUT":
                r = requests.put(url, headers=hdrs, data=data, timeout=10)
            elif method.upper() == "DELETE":
                r = requests.delete(url, headers=hdrs, timeout=10)
            else:
                r = requests.request(method, url, headers=hdrs, data=data, timeout=10)
        except requests.RequestException as e:
            print(f"    [!] {label}: request failed ({e})")
            continue

        status = r.status_code
        # A 2xx/3xx means the action was accepted → CSRF likely works
        accepted = 200 <= status < 400
        verdict = "ACCEPTED — likely vulnerable" if accepted else "rejected"

        print(f"    [{label}] HTTP {status} — {verdict}  ({len(r.content)} bytes)")
        results.append((label, status, accepted, r.text[:120]))

        # Heuristic: tokens often produce specific error strings
        body_lower = r.text.lower()
        for keyword in ("csrf", "token", "forbidden", "invalid", "missing"):
            if keyword in body_lower and not accepted:
                print(f"        └─ response mentions '{keyword}' → protection may exist")

    return results


# ---------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="CSRF vulnerability scanner")
    ap.add_argument("--source", help="Path to source file for static scan")
    ap.add_argument("--url", help="Target URL for dynamic scan")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--cookie", default="", help="Session cookie value, e.g. 'session=abc'")
    ap.add_argument("--data", default="", help="Form body, e.g. 'to=bob&amount=1'")
    args = ap.parse_args()

    if not args.source and not args.url:
        ap.error("Provide --source, --url, or both")

    if args.source:
        static_scan(args.source)

    if args.url:
        dynamic_scan(args.url, args.method, args.cookie, args.data)


if __name__ == "__main__":
    main()