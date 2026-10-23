import os, sqlite3, uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("TRUSTVAULT_DATA", ROOT / "instance"))
UPLOAD_DIR = DATA_DIR / "private_uploads"
DB_PATH = DATA_DIR / "trustvault.sqlite3"
ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}
MAX_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET", "DEV-ONLY-change-this-before-deployment"),
    WTF_CSRF_TIME_LIMIT=28800,
    MAX_CONTENT_LENGTH=MAX_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
CSRFProtect(app)
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def connect_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    with connect_db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
          active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS documents(
          id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id),
          original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
          category TEXT NOT NULL DEFAULT 'General', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS permissions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
          granted_by INTEGER NOT NULL REFERENCES users(id), granted_at TEXT NOT NULL,
          UNIQUE(document_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
          username_snapshot TEXT NOT NULL, document_id INTEGER, action TEXT NOT NULL,
          outcome TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        """)
        # Seed demo accounts only when the database has no users. Change passwords before deployment.
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            demo = [
                ("admin", "AdminDemo123!", "admin"),
                ("owner", "OwnerDemo123!", "owner"),
                ("viewer", "ViewerDemo123!", "viewer"),
            ]
            con.executemany("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            [(u, generate_password_hash(p), r) for u,p,r in demo])

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def audit(action, outcome, document_id=None, details=""):
    user_id = session.get("user_id")
    username = session.get("username", "anonymous")
    with connect_db() as con:
        con.execute("""INSERT INTO audit_logs(actor_id,username_snapshot,document_id,action,outcome,details,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (user_id, username, document_id, action, outcome, details[:300], now()))

@app.before_request
def load_user():
    g.user = None
    if session.get("user_id"):
        with connect_db() as con:
            g.user = con.execute("SELECT id,username,role,active FROM users WHERE id=?",
                                 (session["user_id"],)).fetchone()
        if not g.user or not g.user["active"]:
            session.clear()
            g.user = None

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                audit("role_denied", "denied", details=request.path)
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator

def get_document(doc_id):
    with connect_db() as con:
        return con.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()

def document_permission(doc, required="read"):
    """Server-side check used by every document route. Owners own their docs; named grants apply to others."""
    if not g.user or not doc:
        return False
    if doc["owner_id"] == g.user["id"]:
        return True
    with connect_db() as con:
        row = con.execute("SELECT permission FROM permissions WHERE document_id=? AND user_id=?",
                          (doc["id"], g.user["id"])).fetchone()
    if not row:
        return False
    return row["permission"] == "edit" or (required == "read" and row["permission"] == "read")

def require_document(doc_id, required="read"):
    doc = get_document(doc_id)
    if not doc or not document_permission(doc, required):
        audit("document_access", "denied", doc_id, f"{required} {request.path}")
        abort(404)  # Avoid confirming whether another user's document exists.
    return doc

@app.route("/")
def index():
    if not g.user:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with connect_db() as con:
            user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            audit("login", "success")
            return redirect(url_for("dashboard"))
        session["username"] = username or "anonymous"
        audit("login", "denied", details="invalid credentials")
        session.pop("username", None)
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", "success")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "").strip()[:60]
    date = request.args.get("date", "").strip()[:10]
    with connect_db() as con:
        docs = con.execute("""
          SELECT DISTINCT d.*, u.username AS owner_name,
          CASE WHEN d.owner_id=? THEN 'owner' ELSE p.permission END AS my_permission
          FROM documents d JOIN users u ON u.id=d.owner_id
          LEFT JOIN permissions p ON p.document_id=d.id AND p.user_id=?
          WHERE (d.owner_id=? OR p.user_id=?)
            AND (?='' OR d.original_name LIKE '%'||?||'%' OR u.username LIKE '%'||?||'%')
            AND (?='' OR d.category=?)
            AND (?='' OR substr(d.created_at,1,10)=?)
          ORDER BY d.id DESC
        """, (g.user["id"],g.user["id"],g.user["id"],g.user["id"],
              q,q,q,category,category,date,date)).fetchall()
    return render_template("dashboard.html", docs=docs, q=q, category=category, date=date)

def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
@role_required("owner")
def upload():
    f = request.files.get("file")
    category = request.form.get("category", "General").strip()[:60] or "General"
    if not f or not f.filename:
        flash("Choose a file first.")
        return redirect(url_for("dashboard"))
    safe = secure_filename(f.filename)
    if not safe or not allowed_file(safe):
        audit("upload", "denied", details="invalid extension")
        flash("File type not allowed. Use PDF, TXT, PNG, JPG, JPEG or DOCX.")
        return redirect(url_for("dashboard"))
    stored = uuid.uuid4().hex
    path = UPLOAD_DIR / stored
    f.save(path)
    if path.stat().st_size > MAX_BYTES:
        path.unlink(missing_ok=True)
        audit("upload", "denied", details="file too large")
        flash("File is too large (maximum 5 MB).")
        return redirect(url_for("dashboard"))
    with connect_db() as con:
        cur = con.execute("INSERT INTO documents(owner_id,original_name,stored_name,category,created_at) VALUES(?,?,?,?,?)",
                          (g.user["id"], safe, stored, category, now()))
        doc_id = cur.lastrowid
    audit("upload", "success", doc_id, f"category={category}")
    flash("Document uploaded.")
    return redirect(url_for("dashboard"))

@app.route("/document/<int:doc_id>/download")
@login_required
def download(doc_id):
    doc = require_document(doc_id, "read")
    path = UPLOAD_DIR / doc["stored_name"]
    if not path.is_file():
        audit("download", "error", doc_id, "stored file missing")
        abort(404)
    audit("download", "success", doc_id)
    return send_file(path, as_attachment=True, download_name=doc["original_name"], conditional=True)

@app.route("/document/<int:doc_id>/share", methods=["POST"])
@role_required("owner")
def share(doc_id):
    doc = get_document(doc_id)
    if not doc or doc["owner_id"] != g.user["id"]:
        audit("permission_grant", "denied", doc_id)
        abort(404)
    target = request.form.get("username", "").strip()
    perm = request.form.get("permission", "read")
    if perm not in ("read", "edit"):
        abort(400)
    with connect_db() as con:
        user = con.execute("SELECT id,role,active FROM users WHERE username=?", (target,)).fetchone()
        if not user or not user["active"] or user["role"] == "admin" or user["id"] == g.user["id"]:
            flash("Choose an active viewer or owner account other than yourself.")
            return redirect(url_for("dashboard"))
        con.execute("""INSERT INTO permissions(document_id,user_id,permission,granted_by,granted_at)
          VALUES(?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,
          granted_by=excluded.granted_by,granted_at=excluded.granted_at""",
          (doc_id,user["id"],perm,g.user["id"],now()))
    audit("permission_grant", "success", doc_id, f"recipient={target}; permission={perm}")
    flash("Permission saved.")
    return redirect(url_for("dashboard"))

@app.route("/document/<int:doc_id>/revoke", methods=["POST"])
@role_required("owner")
def revoke(doc_id):
    doc = get_document(doc_id)
    if not doc or doc["owner_id"] != g.user["id"]:
        audit("permission_revoke", "denied", doc_id)
        abort(404)
    target = request.form.get("username", "").strip()
    with connect_db() as con:
        user = con.execute("SELECT id FROM users WHERE username=?", (target,)).fetchone()
        if user:
            con.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?", (doc_id,user["id"]))
    audit("permission_revoke", "success", doc_id, f"recipient={target}")
    flash("Permission revoked if it existed.")
    return redirect(url_for("dashboard"))

@app.route("/document/<int:doc_id>/delete", methods=["POST"])
@role_required("owner")
def delete_document(doc_id):
    doc = get_document(doc_id)
    if not doc or doc["owner_id"] != g.user["id"]:
        audit("delete", "denied", doc_id)
        abort(404)
    # Audit before deleting metadata so the document ID remains recorded.
    audit("delete", "success", doc_id, f"name={doc['original_name']}")
    (UPLOAD_DIR / doc["stored_name"]).unlink(missing_ok=True)
    with connect_db() as con:
        con.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    flash("Document deleted.")
    return redirect(url_for("dashboard"))

@app.route("/admin/activity")
@role_required("admin")
def activity():
    with connect_db() as con:
        logs = con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300").fetchall()
    return render_template("activity.html", logs=logs)

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You are not allowed to perform this action."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested resource was not found or is not available to you."), 404

@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", code=413, message="Upload too large. Maximum size is 5 MB."), 413

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
