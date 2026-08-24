# Lab 02 — Local verification evidence

- Target: learner-owned loopback service `127.0.0.1:18765`
- Scope: loopback only
- Commit tested: `f02d028c4e6812f18911926198b18f93b22f8cbf`
- Verification: `FAIL -> hardening -> PASS`
- Timestamp: `2026-08-24T14:28:13+02:00`

## Before hardening

Exit code: `1`

```json
{
    "schema_version": "1",
    "tool_version": "1.0.0",
    "requested_url": "http://127.0.0.1:18765/",
    "final_url": "http://127.0.0.1:18765/",
    "status": 200,
    "redirect_count": 0,
    "headers": {
        "host": [
            "127.0.0.1:18765"
        ],
        "date": [
            "Mon, 24 Aug 2026 12:28:13 GMT"
        ],
        "connection": [
            "close"
        ],
        "content-type": [
            "text/plain; charset=utf-8"
        ]
    },
    "warnings": [],
    "findings": [
        {
            "id": "hsts",
            "header": "Strict-Transport-Security",
            "status": "NOT_APPLICABLE",
            "severity": "HIGH",
            "observed": null,
            "rationale": "HSTS is established by HTTPS responses.",
            "recommendation": "Use HTTPS before evaluating HSTS.",
            "limitations": null,
            "evidence": "header absent"
        },
        {
            "id": "csp",
            "header": "Content-Security-Policy",
            "status": "FAIL",
            "severity": "HIGH",
            "observed": null,
            "rationale": "No CSP was observed.",
            "recommendation": "Define an application-appropriate CSP.",
            "limitations": null,
            "evidence": "header absent"
        },
        {
            "id": "nosniff",
            "header": "X-Content-Type-Options",
            "status": "FAIL",
            "severity": "MEDIUM",
            "observed": null,
            "rationale": "MIME sniffing protection was not observed.",
            "recommendation": "Set X-Content-Type-Options: nosniff.",
            "limitations": null,
            "evidence": "header absent"
        },
        {
            "id": "frame",
            "header": "X-Frame-Options",
            "status": "FAIL",
            "severity": "MEDIUM",
            "observed": null,
            "rationale": "Legacy frame protection was not observed.",
            "recommendation": "Prefer CSP frame-ancestors; X-Frame-Options may remain defense in depth.",
            "limitations": "v1 does not fully parse frame-ancestors.",
            "evidence": "header absent"
        },
        {
            "id": "referrer",
            "header": "Referrer-Policy",
            "status": "FAIL",
            "severity": "LOW",
            "observed": null,
            "rationale": "No explicit referrer policy was observed.",
            "recommendation": "Set an explicit privacy-appropriate policy.",
            "limitations": null,
            "evidence": "header absent"
        },
        {
            "id": "permissions",
            "header": "Permissions-Policy",
            "status": "FAIL",
            "severity": "LOW",
            "observed": null,
            "rationale": "No Permissions-Policy was observed.",
            "recommendation": "Define feature permissions.",
            "limitations": null,
            "evidence": "header absent"
        }
    ],
    "status_counts": {
        "NOT_APPLICABLE": 1,
        "FAIL": 5
    },
    "severity_counts": {
        "HIGH": 2,
        "MEDIUM": 2,
        "LOW": 2
    }
}
```

## Applied hardening

- Content-Security-Policy
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: no-referrer
- Permissions-Policy

HSTS remains `NOT_APPLICABLE` because this controlled fixture uses
plain HTTP over loopback.

## After hardening

Exit code: `0`

```json
{
    "schema_version": "1",
    "tool_version": "1.0.0",
    "requested_url": "http://127.0.0.1:18765/",
    "final_url": "http://127.0.0.1:18765/",
    "status": 200,
    "redirect_count": 0,
    "headers": {
        "host": [
            "127.0.0.1:18765"
        ],
        "date": [
            "Mon, 24 Aug 2026 12:28:13 GMT"
        ],
        "connection": [
            "close"
        ],
        "content-security-policy": [
            "default-src 'self'"
        ],
        "x-content-type-options": [
            "nosniff"
        ],
        "x-frame-options": [
            "DENY"
        ],
        "referrer-policy": [
            "no-referrer"
        ],
        "permissions-policy": [
            "camera=(), microphone=()"
        ],
        "content-type": [
            "text/plain; charset=utf-8"
        ]
    },
    "warnings": [],
    "findings": [
        {
            "id": "hsts",
            "header": "Strict-Transport-Security",
            "status": "NOT_APPLICABLE",
            "severity": "HIGH",
            "observed": null,
            "rationale": "HSTS is established by HTTPS responses.",
            "recommendation": "Use HTTPS before evaluating HSTS.",
            "limitations": null,
            "evidence": "header absent"
        },
        {
            "id": "csp",
            "header": "Content-Security-Policy",
            "status": "PASS",
            "severity": "HIGH",
            "observed": "default-src 'self'",
            "rationale": "A non-empty CSP was observed.",
            "recommendation": "Review policy strength separately.",
            "limitations": "v1 does not fully analyze CSP strength.",
            "evidence": "observed: default-src 'self'"
        },
        {
            "id": "nosniff",
            "header": "X-Content-Type-Options",
            "status": "PASS",
            "severity": "MEDIUM",
            "observed": "nosniff",
            "rationale": "nosniff is enabled.",
            "recommendation": "Keep it enabled.",
            "limitations": null,
            "evidence": "observed: nosniff"
        },
        {
            "id": "frame",
            "header": "X-Frame-Options",
            "status": "PASS",
            "severity": "MEDIUM",
            "observed": "DENY",
            "rationale": "A recognized frame restriction is present.",
            "recommendation": "Prefer CSP frame-ancestors as the modern mechanism.",
            "limitations": null,
            "evidence": "observed: DENY"
        },
        {
            "id": "referrer",
            "header": "Referrer-Policy",
            "status": "PASS",
            "severity": "LOW",
            "observed": "no-referrer",
            "rationale": "Policy is in the v1 privacy-preserving set.",
            "recommendation": "Confirm it matches application needs.",
            "limitations": null,
            "evidence": "observed: no-referrer"
        },
        {
            "id": "permissions",
            "header": "Permissions-Policy",
            "status": "PASS",
            "severity": "LOW",
            "observed": "camera=(), microphone=()",
            "rationale": "A non-empty policy was observed.",
            "recommendation": "Review directives separately.",
            "limitations": "v1 does not audit directive strength.",
            "evidence": "observed: camera=(), microphone=()"
        }
    ],
    "status_counts": {
        "NOT_APPLICABLE": 1,
        "PASS": 5
    },
    "severity_counts": {
        "HIGH": 2,
        "MEDIUM": 2,
        "LOW": 2
    }
}
```

## Result

**PASS — required local security transition observed.**
