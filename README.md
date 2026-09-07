# PortSwigger Web Security Academy — Lab Writeups

Writeups and evidence from labs I've solved on [PortSwigger's Web Security Academy](https://portswigger.net/web-security), documenting the vulnerability, my exploitation methodology using Burp Suite, root cause analysis, and remediation advice for each.

This repo is part of my ongoing hands-on practice in web application security testing.

## About Me

**Shaistha Khanum** — Cybersecurity professional based in Luton, UK, with 8 years of enterprise IT experience across IAM, cloud infrastructure, networking, and security operations. MSc Cyber Security (Distinction), CompTIA Security+, TryHackMe Top 4%.

- LinkedIn: [linkedin.com/in/shaistha-khanum-33b396a4](https://linkedin.com/in/shaistha-khanum-33b396a4/)
- GitHub: [github.com/shaistha74](https://github.com/shaistha74)
- Technical writing: Medium & LinkedIn under my own name and the **EncodedVoices** brand

## Why This Repo

I use these labs to build and demonstrate practical, hands-on offensive security skills — going beyond theory to actually intercepting, modifying, and replaying HTTP requests with Burp Suite, then documenting findings the way I would in a real pentest report.

## Repo Structure

Writeups are grouped by vulnerability category. Each lab has its own folder containing a `README.md` writeup and a `screenshots/` folder with evidence:

```
portswigger/
├── README.md                                              ← you are here
└── path-traversal/
    ├── path-traversal-notes.md                            ← condensed study notes / bypass cheat-sheet
    ├── file-path-traversal-non-recursive-stripping/
    │   ├── README.md
    │   └── screenshots/
    ├── file-path-traversal-absolute-path-bypass/
    │   ├── README.md
    │   └── screenshots/
    ├── file-path-traversal-superfluous-url-decode/
    │   ├── README.md
    │   └── screenshots/
    ├── file-path-traversal-start-of-path-validation/
    │   ├── README.md
    │   └── screenshots/
    └── file-path-traversal-null-byte-bypass/
        ├── README.md
        └── screenshots/
```

Every lab writeup follows the same format: **Lab Description → Vulnerability Overview → Methodology → Result → Root Cause → Evidence → Remediation**.

As I work through more categories on the Academy (SSRF, SQL injection, access control, etc.), each will get its own top-level folder alongside `path-traversal/`, following the same pattern.

## Labs Solved

### Path Traversal

| Lab | Bypass Technique | Writeup |
|---|---|---|
| Traversal sequences stripped non-recursively | Nested sequence (`....//`) collapses back into `../` after a single-pass strip | [README](./path-traversal/file-path-traversal-non-recursive-stripping/README.md) |
| Traversal sequences blocked with absolute path bypass | Supplying an absolute path (`/etc/passwd`) skips the traversal filter entirely — no `../` needed | [README](./path-traversal/file-path-traversal-absolute-path-bypass/README.md) |
| Traversal sequences stripped with superfluous URL-decode | Double URL-encoding (`%252e%252e%252f`) survives the filter, then decodes into `../` on the app's own extra decode pass | [README](./path-traversal/file-path-traversal-superfluous-url-decode/README.md) |
| Validation of start of path | Prefix stays valid (`/var/www/images/`) while `../` after it walks back out to root | [README](./path-traversal/file-path-traversal-start-of-path-validation/README.md) |
| Validation of file extension with null byte bypass | Embedded null byte (`%00`) truncates the path before the filesystem, so a fake `.jpg` suffix satisfies the extension check without ever being read | [README](./path-traversal/file-path-traversal-null-byte-bypass/README.md) |

📓 See [`path-traversal-notes.md`](./path-traversal/path-traversal-notes.md) for a condensed reference — bypass cheat-sheet, testing checklist, and pentest finding template.

## Methodology (applies across all labs)

1. Browse the target application and identify parameters that reference files (`filename`, `path`, `document`, etc.).
2. Intercept the relevant request in **Burp Suite Proxy** and send it to **Repeater**.
3. Confirm baseline/normal behaviour first.
4. Attempt standard traversal payloads, then progressively try encoded, nested, absolute-path, and null-byte variants depending on what defence is in place.
5. Compare response status, length, and content to confirm success.
6. Capture request/response evidence and the lab's "Solved" confirmation.

## Key Takeaway

A single blacklist check (stripping `../` once, blocking a leading `../`, requiring a specific extension) is rarely enough on its own — every lab in this series demonstrates a different way that a narrow, pattern-based filter can be satisfied on paper while the underlying filesystem still resolves to a completely different location. The consistent fix across all of them is the same: **canonicalize the fully resolved path and verify it stays within the intended base directory**, rather than trying to out-guess every possible encoding of a bad pattern.

## Tools Used

- [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload) — intercepting proxy, Repeater
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free, hands-on labs

## Disclaimer

All testing was performed against PortSwigger's own intentionally vulnerable lab environments, provisioned specifically for this purpose. None of the techniques here were used against systems I don't have explicit authorization to test.
