# TrustVault Threat Model

Update this file after testing your actual application. Do not claim a mitigation is complete until you have verified it.

## 1. Insecure direct object reference (ID guessing)
Threat: A user changes a document ID in a URL.
Mitigation: `require_document()` checks ownership or a current named permission on each download; inaccessible IDs return 404.
Verification: `tests/test_security.py::test_viewer_cannot_download_unshared_document`.

## 2. Direct file storage access
Threat: A visitor tries to fetch an uploaded file without using the application.
Mitigation: Files are stored in `instance/private_uploads`, outside Flask's static directory, and served only through the download route.
Verification: Confirm the storage directory is not web-served in the deployed host.

## 3. Permission revocation delay
Threat: A user continues accessing a document after access is revoked.
Mitigation: Current database permissions are checked for each download; do not use public or long-lived file URLs.
Accepted limitation: A file already downloaded by a recipient cannot be remotely erased from their device.

## 4. Audit log tampering
Threat: An attacker with database or server access edits event records.
Mitigation: Ordinary app routes do not expose audit-log editing. For production, send logs to a separately controlled append-only/tamper-evident store.
Accepted limitation: SQLite audit records are not independently tamper-proof against a server/database administrator.

## 5. Malicious or oversized uploads
Threat: An attacker uploads a dangerous or very large file.
Mitigation: Limit request size, allowlist extensions, use safe storage names, and never execute uploads.
Accepted limitation: Extension checks alone do not prove file content is safe. Production should inspect file signatures and scan uploads.

## 6. Session theft / CSRF
Threat: A stolen session or forged form request is used.
Mitigation: HttpOnly and SameSite session cookies; Flask-WTF CSRF tokens on forms. Set HTTPS and `COOKIE_SECURE=1` in production.
Accepted limitation: This demo does not implement MFA or enterprise SSO.

## 7. Password guessing
Threat: Repeated login attempts guess a password.
Mitigation: Passwords are hashed using Werkzeug.
Accepted limitation: Rate limiting and lockout are not implemented in this demo.

## 8. Audit identity spoofing
Threat: A user attempts to make an action appear to belong to another user.
Mitigation: The actor ID is taken from the authenticated session, not a form field.
Verification: Review all audit-writing calls and test denied requests.

## 9. Admin privilege confusion
Threat: An administrator assumes they can read every document.
Mitigation: Admin activity access is separate from document access; admin role does not bypass document permission checks.
Accepted limitation: Admin account recovery and user-management UI are not implemented.

## 10. Secret key exposure
Threat: A predictable Flask secret key enables session forgery.
Mitigation: Set a unique `TRUSTVAULT_SECRET` environment variable before deployment.
Accepted limitation: The development fallback secret is public in source and must never be used in production.
