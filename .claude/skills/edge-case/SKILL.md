---
name: edge-case
description: secure coding with edge case consideration
---
## Purpose

Use this skill when writing, reviewing, or debugging code where edge cases could create security issues.

## Checklist

Check for:

* Empty, null, malformed, oversized, or unexpected input
* Type confusion, encoding issues, Unicode tricks, and locale differences
* Injection risks: SQL, command, LDAP, XML, template, path, prompt, and header injection
* Authentication bypasses, weak session handling, missing authorization checks
* Insecure defaults, hardcoded secrets, verbose errors, unsafe logging
* Race conditions, replay attacks, double-submit bugs, and idempotency issues
* Path traversal, unsafe file upload/download, symlink abuse
* SSRF, open redirects, CORS mistakes, CSRF, XSS
* Deserialization, dependency, supply-chain, and configuration risks
* Rate limits, timeouts, retries, resource exhaustion, and DoS cases

## Rules

* Validate at trust boundaries.
* Normalize before validating when relevant.
* Prefer allowlists over blocklists.
* Enforce authorization server-side.
* Fail closed, not open.
* Use safe library APIs instead of string-built queries, shells, parsers, or crypto.
* Never log secrets, tokens, passwords, or sensitive payloads.
* Treat client-side checks as advisory only.
* Make errors useful to developers but vague to attackers.
* Add tests for abuse cases, not just happy paths.

## Output Format

When reviewing code, respond with:

1. **Critical risks**
2. **Edge cases**
3. **Fixes**
4. **Security tests**

Keep findings specific, actionable, and tied to the code.
