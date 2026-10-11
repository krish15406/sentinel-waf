
import re
from datetime import datetime
from urllib.parse import unquote_plus


RULES = {
    "SQL Injection": [
        re.compile(r"\bunion\s+select\b", re.IGNORECASE),
        re.compile(r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.IGNORECASE),
        re.compile(r";\s*(drop|delete|update|insert)\b", re.IGNORECASE),
        re.compile(r"\b(sleep|benchmark)\s*\(", re.IGNORECASE),
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"<\s*script\b", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),
        re.compile(r"<\s*iframe\b", re.IGNORECASE),
    ],
}


def inspect_request(method, path, data="", ip="127.0.0.1"):
    content = unquote_plus(f"{method} {path} {data}")

    detected_attack = None

    for attack_type, patterns in RULES.items():
        if any(pattern.search(content) for pattern in patterns):
            detected_attack = attack_type
            break

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "method": method,
        "path": path,
        "ip": ip,
        "status": "BLOCKED" if detected_attack else "ALLOWED",
        "attack_type": detected_attack or "None",
        "action": "Block" if detected_attack else "Allow",
    }


if __name__ == "__main__":
    tests = [
        ("GET", "/", "welcome"),
        ("GET", "/search", "q=UNION+SELECT+username"),
        ("GET", "/search", "q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ]

    for test in tests:
        print(inspect_request(*test))
