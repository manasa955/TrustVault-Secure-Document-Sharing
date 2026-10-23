# TrustVault — Secure Document Sharing

A two-day MVP for the Snovasys Fresher Hiring Challenge. Built with Flask, SQLite, HTML and CSS.

## Features
- Login with Admin, Owner and Viewer roles
- Owner document upload, search and private storage
- Per-document named read/edit grants and revocation
- Server-side access checks before download
- Audit events for logins, uploads, downloads, permission changes, deletes and denied document access
- Admin activity view
- File extension and upload-size checks
- CSRF protection for HTML forms
- Automated access-control tests

## Requirements
Python 3.10+ recommended.

## Run locally (Windows)
```bat
cd TrustVault
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

If `py` is unavailable, use `python` in place of `py`.

## Demo accounts
- Admin: `admin` / `AdminDemo123!`
- Owner: `owner` / `OwnerDemo123!`
- Viewer: `viewer` / `ViewerDemo123!`

These are demo credentials. Change them and set a unique `TRUSTVAULT_SECRET` before deployment. Do not use demo passwords for a public deployment.

## Run tests
```bat
python -m pytest -q
```

## Security notes
- Uploaded files are stored under `instance/private_uploads`, not under the static web directory.
- Every download checks current ownership or current permission in the database.
- Unauthorised document requests return 404 to avoid disclosing document existence.
- Revocation blocks later application downloads. It cannot erase a file already downloaded by a recipient.
- SQLite audit logs are not tamper-proof against a server/database administrator. Production should export events to a separately controlled append-only or tamper-evident service.
- The demo has no rate limiting, MFA, malware scanning, versioning, or user-management UI.
- Before deployment, configure HTTPS, a strong secret key, secure cookies, persistent private storage and a production WSGI server.

## Roles
- Admin: view audit activity; does not automatically get document content access.
- Owner: upload, download, share, revoke and delete their own documents.
- Viewer: download documents explicitly shared with them; cannot upload or manage permissions.

## API / route permissions
| Route | Methods | Allowed caller |
|---|---|---|
| `/login` | GET, POST | Public |
| `/logout` | POST | Authenticated |
| `/dashboard` | GET | Authenticated; only own/shared documents listed |
| `/upload` | POST | Owner |
| `/document/<id>/download` | GET | Owner or user with current read/edit grant |
| `/document/<id>/share` | POST | Owner of that document |
| `/document/<id>/revoke` | POST | Owner of that document |
| `/document/<id>/delete` | POST | Owner of that document |
| `/admin/activity` | GET | Admin |

## Before public submission
1. Change the demo passwords and secret key.
2. Deploy with HTTPS and secure cookies.
3. Confirm private uploads persist and are not publicly served.
4. Run tests against a fresh database.
5. Expand `THREATS.md` based on actual attacks you tried.
6. Complete `PROMPTS.md` with genuine dated entries and real commits.
7. Create a public Git repository, add commit history, and record a five-minute demo.
## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- Flask-WTF for CSRF protection
- Pytest for security testing

## User Roles

- **Admin:** Views application activity and audit events.
- **Owner:** Uploads documents, searches files, and grants or revokes access.
- **Viewer:** Accesses only documents shared with them.

## Installation

1. Install Python 3.13 or a compatible supported Python version.
2. Open the project folder in VS Code.
3. Open the terminal inside the `TrustVault` folder.
4. Install the dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

## Run the Application

Start the application:

'''bash
python app.py
```

Open this address in your browser:

`http://127.0.0.1:5000`

## Run Security Tests

Run:

```bash
python -m pytest -v
```

The current security test suite contains three tests covering unauthorized downloads, permission revocation, and viewer upload restrictions.

## Security Features

- Role-based access control
- Per-document read/edit permissions
- Permission revocation
- Private file storage
- Server-side download authorization
- CSRF protection
- File extension and upload-size checks
- Audit logging

## Important Security Notes

- Change all demo passwords and development secrets before deployment.
- Never publish private documents, local databases containing sensitive information, or secret keys.
- Use HTTPS and production-grade configuration before exposing the application to the internet.

## Project Status

TrustVault is a local prototype for secure document sharing. Additional testing and security review are recommended before production use.
