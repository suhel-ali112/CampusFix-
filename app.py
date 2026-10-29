import base64
import hmac
import json
import os
import re
import secrets
import urllib.error
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import timedelta
from email.message import EmailMessage
from functools import wraps
from urllib import parse as urlparse
from urllib import request as urlrequest

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session, url_for
from jinja2 import TemplateNotFound
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db_connection, init_db

try:  # optional: load variables from a .env file
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass



# Config

def env_flag(name, default=False):
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ('1', 'true', 'yes', 'on')


app = Flask(__name__)

if env_flag('TRUST_PROXY'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_secret = os.environ.get('SECRET_KEY')
if not _secret:
    _secret = secrets.token_hex(32)
    print('WARNING: SECRET_KEY is not set. Using a random key - everyone is logged out on every restart.')
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_flag('COOKIE_SECURE'),       # set COOKIE_SECURE=1 when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
)

SMTP_EMAIL = os.environ.get('SMTP_EMAIL', '')
SMTP_APP_PASSWORD = os.environ.get('SMTP_APP_PASSWORD', '')
REQUIRE_EMAIL_OTP = env_flag('REQUIRE_EMAIL_OTP', True)     # signup needs a verified email

BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '').strip()
BREVO_SENDER_EMAIL = os.environ.get('BREVO_SENDER_EMAIL', '').strip()

ADMIN_DB_ROLES = {'hod', 'admin'}
CATEGORIES = {'Hostel', 'Mess', 'Classroom', 'Electricity', 'Water', 'Wi-Fi', 'Cleanliness', 'Other'}
DEPTS = ['Hostel Administration', 'Mess & Catering', 'Maintenance', 'IT Support', 'General Administration']
STAFF_ROLES = ['Warden', 'Assistant Warden', 'Mess Manager', 'IT Support Staff', 'Maintenance Staff', 'Administrative Staff']

PRIORITY_TO_DB = {'low': 'Low', 'normal': 'Medium', 'medium': 'Medium',
                  'high': 'High', 'important': 'High', 'urgent': 'Urgent'}
STATUS_TO_UI = {'pending': 'submitted', 'in progress': 'review', 'resolved': 'resolved'}
STATUS_TO_DB = {'submitted': 'Pending', 'review': 'In Progress', 'resolved': 'Resolved'}

MIN_REPORT = 20
MAX_COMPLAINT_PHOTO = 3 * 1024 * 1024
MAX_PROFILE_PHOTO = 1024 * 1024



# Small helpers

class DBError(Exception):
    pass


@contextmanager
def db(dictionary=False):
    """Open a connection + cursor and always close them. Roll back on error."""
    conn = get_db_connection()
    if not conn:
        raise DBError('Database connection failed')
    cur = conn.cursor(dictionary=dictionary, buffered=True)
    try:
        yield conn, cur
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            cur.close()
        finally:
            conn.close()


def ok(message=None, **extra):
    body = {'success': True}
    if message:
        body['message'] = message
    body.update(extra)
    return jsonify(body)


def fail(message, code=400):
    return jsonify({'success': False, 'message': message}), code


def clean(v, maxlen, default=''):
    if v is None:
        return default
    return str(v).strip()[:maxlen]


EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')


def norm_email(v):
    return clean(v, 120).lower()


def valid_phone(v):
    return v == '' or bool(re.fullmatch(r'\d{10}', v))


def to_ms(dt):
    return int(dt.timestamp() * 1000) if dt else None


def cf_id(n):
    # "26" is kept so IDs already stored on students' devices stay valid.
    return f"CF-26-{int(n):04d}"


YEAR_RE = re.compile(r'^(.*?)\s*((?:PG\s+)?\d+(?:st|nd|rd|th)\s+Year)$', re.I)
CID_RE = re.compile(r'^(?:CF-\d{2}-)?(\d{1,10})$')


def parse_cid(raw):
    m = CID_RE.match(str(raw or '').strip())
    return int(m.group(1)) if m else None


def normalize_role(raw):
    r = (raw or '').strip().lower()
    if r in ADMIN_DB_ROLES:
        return 'admin'
    if r == 'student':
        return 'student'
    return None


def status_ui(v):
    return STATUS_TO_UI.get(str(v or '').strip().lower(), 'submitted')


# ---------- images (stored as data-URLs, same as before) ----------
DATA_URL_RE = re.compile(r'^data:image/(?:jpeg|jpg|png|webp);base64,([A-Za-z0-9+/=\r\n]+)$')


def sniff_image(raw):
    if raw[:3] == b'\xff\xd8\xff':
        return 'jpeg'
    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'webp'
    return None


def check_image_bytes(raw, max_bytes):
    """-> (data_url, subtype) or None. Checks real file signature and size."""
    if not raw or len(raw) > max_bytes:
        return None
    sub = sniff_image(raw)
    if not sub:
        return None
    return f"data:image/{sub};base64,{base64.b64encode(raw).decode()}", sub


def check_data_url(s, max_bytes):
    if not isinstance(s, str) or len(s) > max_bytes * 4 // 3 + 200:
        return None
    m = DATA_URL_RE.match(s.strip())
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1))
    except Exception:
        return None
    res = check_image_bytes(raw, max_bytes)
    return (res[0], raw, res[1]) if res else None


# ---------- passwords ----------
HASH_PREFIXES = ('scrypt:', 'pbkdf2:')


def verify_password(stored, given):
    """-> (is_valid, needs_upgrade). Supports old plain-text rows and upgrades them."""
    if not stored or given is None:
        return False, False
    if str(stored).startswith(HASH_PREFIXES):
        return check_password_hash(stored, given), False
    good = hmac.compare_digest(str(stored).encode(), str(given).encode())
    return good, good


_PW_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'


def gen_password(n=10):
    return ''.join(secrets.choice(_PW_CHARS) for _ in range(n))


# ---------- tiny in-memory rate limiting (single process) ----------
_hits = defaultdict(deque)
_fails = defaultdict(deque)


_last_sweep = 0.0


def sweep_memory(now):
    global _last_sweep
    if now - _last_sweep < 60:
        return
    _last_sweep = now
    for store, ttl in ((_hits, 3600), (_fails, 300)):
        for k in [k for k, q in store.items() if not q or now - q[-1] > ttl]:
            store.pop(k, None)
    for k in [k for k, v in _otps.items() if v['exp'] < now]:
        _otps.pop(k, None)
    for k in [k for k, t in _verified.items() if t < now]:
        _verified.pop(k, None)


def too_many(key, limit, window):
    now = time.time()
    sweep_memory(now)
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def login_locked(key, limit=5, window=300):
    now = time.time()
    q = _fails[key]
    while q and now - q[0] > window:
        q.popleft()
    return len(q) >= limit


def login_failed(key):
    _fails[key].append(time.time())


# ---------- auth ----------
def require_role(*roles, api=True):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if session.get('role') not in roles:
                if api:
                    return fail('Unauthorized', 401)
                return redirect(url_for('index'))
            return f(*a, **kw)
        return wrapper
    return deco


# a staff member still on the temporary password may only do these
STAFF_PW_ALLOWED = {'staff_dashboard', 'api_staff_me', 'api_staff_change_password', 'logout'}


def staff_required(api=True):
    """Staff must be logged in AND still active (re-checked on every request)."""
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            sid = session.get('staff_id')
            row = None
            if session.get('role') == 'staff' and sid:
                with db(True) as (conn, cur):
                    cur.execute('SELECT * FROM staff WHERE id = %s AND active = 1', (sid,))
                    row = cur.fetchone()
            if not row:
                if session.get('role') == 'staff':   # only drop a staff session, never a student/admin one
                    session.clear()
                if api:
                    return fail('Please log in again', 401)
                return redirect(url_for('index'))
            if row.get('must_change_password') and request.endpoint not in STAFF_PW_ALLOWED:
                if api:
                    return jsonify({'success': False, 'code': 'must_change',
                                    'message': 'Please set a new password first.'}), 403
                return redirect(url_for('staff_dashboard'))
            g.staff = row
            return f(*a, **kw)
        return wrapper
    return deco


def render_any(names, **ctx):
    """Template file names are case-sensitive on Linux; try each spelling."""
    for n in names:
        try:
            return render_template(n, **ctx)
        except TemplateNotFound:
            continue
    raise TemplateNotFound(names[0])


# ======================================================================
# Email
# ======================================================================
def send_email(to, subject, body, attachment=None):
    if not BREVO_API_KEY or not BREVO_SENDER_EMAIL:
        raise RuntimeError(
            'BREVO_API_KEY / BREVO_SENDER_EMAIL are not configured'
        )

    payload = {
        "sender": {
            "name": "CampusFix",
            "email": BREVO_SENDER_EMAIL
        },
        "to": [{"email": to}],
        "subject": subject,
        "textContent": body
    }

    if attachment:
        raw, sub = attachment
        payload["attachment"] = [{
            "name": f"fix.{sub}",
            "content": base64.b64encode(raw).decode("utf-8")
        }]

    data = json.dumps(payload).encode("utf-8")

    req = urlrequest.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=data,
        headers={
            "api-key": BREVO_API_KEY,
            "accept": "application/json",
            "content-type": "application/json"
        },
        method="POST"
    )

    try:
        with urlrequest.urlopen(req, timeout=15) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError(
                    f"Brevo email failed: HTTP {response.status}"
                )
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Brevo API error {e.code}: {error_body}"
        ) from e


def send_email_async(*args, **kwargs):
    def run():
        try:
            send_email(*args, **kwargs)
        except Exception as e:
            app.logger.warning('Email not sent: %s', e)
    threading.Thread(target=run, daemon=True).start()


# ======================================================================
# Database: add missing columns / tables, widen small columns
# ======================================================================
REQUIRED_COLUMNS = [
    ('users', 'emp_id', 'VARCHAR(40) NULL'),
    ('users', 'dept', 'VARCHAR(80) NULL'),
    ('complaints', 'client_cid', 'VARCHAR(64) NULL'),
    ('complaints', 'assigned_to', 'INT NULL'),
    ('complaints', 'resolved_at', 'DATETIME NULL'),
    ('complaints', 'resolved_by', 'VARCHAR(100) NULL'),
    ('complaints', 'notified_at', 'DATETIME NULL'),
    ('complaints', 'resolution_note', 'TEXT NULL'),
    ('complaints', 'resolution_photo', 'LONGTEXT NULL'),
    ('complaints', 'rating', 'TINYINT NULL'),
    ('staff', 'created_at', 'TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP'),
    ('staff', 'active', 'TINYINT NOT NULL DEFAULT 1'),
    ('staff', 'profile_photo', 'LONGTEXT NULL'),
    ('complaints', 'escalated', 'TINYINT NOT NULL DEFAULT 0'),
    ('staff', 'must_change_password', 'TINYINT NOT NULL DEFAULT 0'),
]
BIG_TEXT_COLUMNS = [('users', 'profile_photo'), ('complaints', 'photo'),
                    ('complaints', 'resolution_photo')]
HASH_COLUMNS = [('users', 'password_hash'), ('staff', 'password')]
# staff text columns: an old INT phone, ENUM role or short VARCHAR makes INSERT fail
STAFF_TEXT_COLUMNS = [('staff', 'name', 100), ('staff', 'email', 120), ('staff', 'dept', 80),
                      ('staff', 'role', 60), ('staff', 'phone', 20)]

CREATE_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS complaint_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    complaint_id INT NOT NULL,
    kind VARCHAR(20) NULL,
    msg VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_log_complaint (complaint_id)
)
"""


def ensure_schema():
    with db(True) as (conn, cur):
        cur.execute('SELECT DATABASE() AS d')
        dbname = cur.fetchone()['d']
        cur.execute("""SELECT TABLE_NAME AS t, COLUMN_NAME AS c, DATA_TYPE AS d,
                              CHARACTER_MAXIMUM_LENGTH AS l, IS_NULLABLE AS n, COLUMN_DEFAULT AS df
                       FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s""", (dbname,))
        cols = {(r['t'].lower(), r['c']): r for r in cur.fetchall()}
        tables = {t for t, _ in cols}

        for table, col, ddl in REQUIRED_COLUMNS:
            if table in tables and (table, col) not in cols:
                cur.execute(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}')
                print(f'schema: added {table}.{col}')
        for table, col in BIG_TEXT_COLUMNS:
            info = cols.get((table, col))
            if info and info['d'].lower() != 'longtext':
                cur.execute(f'ALTER TABLE {table} MODIFY {col} LONGTEXT NULL')
                print(f'schema: widened {table}.{col}')
        for table in ('staff', 'users', 'complaints', 'complaint_log'):
            info = cols.get((table, 'created_at'))
            if info and info['n'] == 'NO' and info['df'] is None:
                kind = info['d'].upper() if info['d'].lower() in ('timestamp', 'datetime') else 'TIMESTAMP'
                cur.execute(f'ALTER TABLE {table} MODIFY created_at {kind} NULL DEFAULT CURRENT_TIMESTAMP')
                print(f'schema: gave {table}.created_at a default value')
        for table, col, length in STAFF_TEXT_COLUMNS:
            info = cols.get((table, col))
            if not info:
                continue
            if info['d'].lower() in ('varchar', 'char') and (info['l'] or 0) >= length:
                continue
            null = 'NOT NULL' if info['n'] == 'NO' else 'NULL'
            cur.execute(f'ALTER TABLE {table} MODIFY {col} VARCHAR({length}) {null}')
            print(f'schema: changed {table}.{col} to VARCHAR({length})')
        for table, col in HASH_COLUMNS:
            info = cols.get((table, col))
            if info and info['d'].lower() in ('varchar', 'char') and (info['l'] or 0) < 255:
                null = 'NOT NULL' if info['n'] == 'NO' else 'NULL'
                cur.execute(f'ALTER TABLE {table} MODIFY {col} VARCHAR(255) {null}')
                print(f'schema: widened {table}.{col}')
        cur.execute(CREATE_LOG_TABLE)
        conn.commit()
        try:  # a retried request can never create the same complaint twice
            cur.execute('SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = %s '
                        'AND TABLE_NAME = %s AND INDEX_NAME = %s', (dbname, 'complaints', 'uq_student_cid'))
            if not cur.fetchone():
                cur.execute('ALTER TABLE complaints ADD UNIQUE INDEX uq_student_cid (student_id, client_cid)')
                conn.commit()
                print('schema: added unique index uq_student_cid')
        except Exception as e:   # e.g. old duplicate rows exist; the app still works without it
            print(f'WARNING: could not add unique index uq_student_cid: {e}')


def bootstrap_admin():
    email = norm_email(os.environ.get('ADMIN_EMAIL'))
    password = os.environ.get('ADMIN_PASSWORD') or ''
    if not email or len(password) < 8:
        return
    with db(True) as (conn, cur):
        cur.execute("SELECT 1 FROM users WHERE role IN ('admin', 'hod') LIMIT 1")
        if cur.fetchone():
            return
        cur.execute("INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'admin')",
                    (clean(os.environ.get('ADMIN_NAME'), 100) or 'Admin', email, generate_password_hash(password)))
        conn.commit()
        print(f'admin created from ADMIN_EMAIL: {email}')


if not env_flag('SKIP_SCHEMA_CHECK'):
    try:
        init_db()
        ensure_schema()
        bootstrap_admin()
    except Exception as e:  # app still starts; the message tells what to fix
        print(f'WARNING: schema check failed: {e}')


# ======================================================================
# Complaint helpers
# ======================================================================
def add_log(cur, complaint_id, msg, kind=None):
    cur.execute('INSERT INTO complaint_log (complaint_id, kind, msg) VALUES (%s, %s, %s)',
                (complaint_id, kind, msg))


def notify(cur, complaint_id, title, message):
    cur.execute('INSERT INTO user_notifications (user_id, complaint_id, title, message) '
                'SELECT student_id, id, %s, %s FROM complaints WHERE id = %s',
                (title[:120], message[:500], complaint_id))


def mail_student(num, subject, body):
    if not (SMTP_EMAIL and SMTP_APP_PASSWORD):
        return
    with db(True) as (conn, cur):
        cur.execute('SELECT u.name, u.email, c.title FROM complaints c '
                    'JOIN users u ON c.student_id = u.id WHERE c.id = %s', (num,))
        r = cur.fetchone()
    if r and r['email']:
        send_email_async(r['email'], subject,
                         f"Hello {r['name'] or 'Student'},\n\n{body.replace('{title}', r['title'] or '')}\n\n- CampusFix")


def fetch_logs(cur, ids=None):
    """-> {complaint_id: [rows]} (all complaints when ids is None)."""
    if ids is not None and not ids:
        return {}
    if ids is None:
        cur.execute('SELECT complaint_id, kind, msg, created_at FROM complaint_log ORDER BY created_at, id')
    else:
        marks = ','.join(['%s'] * len(ids))
        cur.execute(f'SELECT complaint_id, kind, msg, created_at FROM complaint_log '
                    f'WHERE complaint_id IN ({marks}) ORDER BY created_at, id', tuple(ids))
    out = defaultdict(list)
    for r in cur.fetchall():
        out[r['complaint_id']].append(r)
    return out


COMPLAINT_COLS = (
    "c.id, c.student_id, c.title, c.description, c.location, c.category, c.priority, c.status, "
    "c.assigned_to, c.escalated, c.rating, c.resolved_at, c.resolved_by, c.notified_at, "
    "c.resolution_note, c.created_at, "
    "(c.photo IS NOT NULL) AS has_photo, (c.resolution_photo IS NOT NULL) AS has_res_photo"
)


def photo_url(row):
    return f"/api/photos/complaint/{row['id']}" if row.get('has_photo') else ''


def resolution_photo_url(row):
    if not row.get('has_res_photo'):
        return ''
    return f"/api/photos/resolution/{row['id']}?v={to_ms(row.get('resolved_at')) or 0}"


def serialize_complaint(row, logs=None, admin=False):
    status = status_ui(row.get('status'))
    created = to_ms(row.get('created_at')) or 0
    resolved = to_ms(row.get('resolved_at'))
    logs = logs or []

    history = [{'s': 'submitted', 'ts': created}]
    history += [{'s': l['kind'], 'ts': to_ms(l['created_at'])} for l in logs if l.get('kind')]

    d = {
        'id': cf_id(row['id']),
        'db_id': row['id'],
        'title': row.get('title') or '',
        'details': row.get('description') or '',
        'address': row.get('location') or '',
        'category': row.get('category') or 'Other',
        'priority': str(row.get('priority') or 'Medium').lower(),
        'status': status,
        'createdAt': created,
        'resolvedAt': resolved if status == 'resolved' else None,
        'assignedTo': str(row['assigned_to']) if row.get('assigned_to') is not None else None,
        'photo': photo_url(row),
        'rating': row.get('rating') or 0,
        'history': history,
        'resolution': None,
        'notifiedAt': to_ms(row.get('notified_at')),
        'escalated': bool(row.get('escalated')),
    }
    if status == 'resolved' and (row.get('resolution_note') or row.get('has_res_photo')):
        d['resolution'] = {'photo': resolution_photo_url(row),
                           'report': row.get('resolution_note') or '',
                           'by': row.get('resolved_by') or 'Admin',
                           'at': resolved}
    if admin:
        d['log'] = [{'t': to_ms(l['created_at']), 'msg': l['msg']} for l in logs]
        d['studentName'] = row.get('student_name') or ''
        d['studentEmail'] = row.get('student_email') or ''
        d['studentPhone'] = row.get('student_phone') or ''
    return d


def serialize_staff(row):
    return {'id': str(row['id']), 'name': row['name'], 'email': row['email'],
            'dept': row.get('dept') or '', 'role': row.get('role') or '',
            'phone': row.get('phone') or '', 'active': bool(row.get('active', 1)),
            'createdAt': to_ms(row.get('created_at')) or 0}


# ======================================================================
# Global hooks
# ======================================================================
@app.after_request
def add_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    if (request.path.startswith('/api/') and not request.path.startswith('/api/photos/')) \
            or request.path.endswith('-dashboard'):
        resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.before_request
def block_cross_site_writes():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        origin = request.headers.get('Origin')
        if origin and urlparse.urlparse(origin).netloc != request.host:
            return fail('Cross-site request blocked', 403)


@app.errorhandler(DBError)
def handle_db_error(e):
    if request.path.startswith('/api/'):
        return fail('Database is not available right now. Please try again.', 503)
    return 'Database is not available right now. Please try again.', 503


@app.errorhandler(Exception)
def handle_any_error(e):
    if isinstance(e, HTTPException):
        if request.path.startswith('/api/'):
            return fail(e.name, e.code or 500)
        return e
    app.logger.exception('Unhandled error on %s', request.path)
    if request.path.startswith('/api/'):
        return fail('Something went wrong on the server.', 500)
    return 'Something went wrong on the server.', 500


# ======================================================================
# Pages + auth
# ======================================================================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/student-dashboard')
@require_role('student', api=False)
def student_dashboard():
    return render_template('student_dashboard.html', student_name=session.get('name'))


@app.route('/admin-dashboard')
@require_role('admin', api=False)
def admin_dashboard():
    return render_any(['admin_dashboard.html', 'Admin_dashboard.html'], admin_name=session.get('name'))


@app.route('/staff-dashboard')
@staff_required(api=False)
def staff_dashboard():
    return render_template('staff_dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------- OTP ----------
OTP_TTL = 300
OTP_MAX_TRIES = 5
VERIFIED_TTL = 900
_otps = {}        # email -> {otp, exp, tries, sent}   (memory: use Redis/DB if you run several workers)
_verified = {}    # email -> expiry


@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json(silent=True) or {}
    email = norm_email(data.get('email'))
    if not EMAIL_RE.match(email):
        return fail('A valid email is required')
    if too_many(f'otp-ip:{request.remote_addr}', 10, 3600):
        return fail('Too many requests. Please try again later.', 429)
    prev = _otps.get(email)
    if prev and time.time() - prev['sent'] < 30:
        return fail('Please wait 30 seconds before asking for another OTP.', 429)
    with db() as (conn, cur):
        cur.execute('SELECT 1 FROM users WHERE LOWER(email) = %s LIMIT 1', (email,))
        if cur.fetchone():
            return fail('An account with this email already exists. Please log in.', 409)

    otp = str(secrets.randbelow(900000) + 100000)
    try:
        send_email(email, 'CampusFix - Email Verification OTP',
                   f'Your 6-digit verification OTP is: {otp}\n\nIt is valid for 5 minutes.')
    except Exception as e:
        app.logger.error('OTP email failed: %s', e)
        return fail('Could not send the OTP right now. Please try again later.', 502)
    _otps[email] = {'otp': otp, 'exp': time.time() + OTP_TTL, 'tries': 0, 'sent': time.time()}
    return ok('OTP sent successfully!')


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json(silent=True) or {}
    email = norm_email(data.get('email'))
    entered = clean(data.get('otp'), 10)
    rec = _otps.get(email)
    if not rec or time.time() > rec['exp']:
        _otps.pop(email, None)
        return jsonify({'success': False, 'message': 'OTP expired. Request a new one.'})
    rec['tries'] += 1
    if rec['tries'] > OTP_MAX_TRIES:
        _otps.pop(email, None)
        return jsonify({'success': False, 'message': 'Too many wrong attempts. Request a new OTP.'})
    if not hmac.compare_digest(rec['otp'], entered):
        return jsonify({'success': False, 'message': 'Wrong OTP.'})
    _otps.pop(email, None)
    _verified[email] = time.time() + VERIFIED_TTL
    return jsonify({'success': True})


# ---------- forgot password (accounts in the users table) ----------
RESET_OTP_TTL = 300
RESET_TOKEN_TTL = 600
_reset_otps = {}     # user_id -> {otp, exp, tries, sent}   (memory: use Redis/DB if you run several workers)
_reset_tokens = {}   # user_id -> {token, exp}   (issued after the OTP is verified)


def _prune(store):
    now = time.time()
    for k in [k for k, v in store.items() if v['exp'] < now]:
        store.pop(k, None)


def _account_for_reset(ident):
    """Find the account by roll number / email (users) or email (staff). -> dict with 'table', or None."""
    ident = clean(ident, 120)
    if not ident:
        return None
    low = ident.lower()
    with db(True) as (conn, cur):
        cur.execute('SELECT id, name, email FROM users WHERE roll_number = %s OR LOWER(email) = %s LIMIT 1',
                    (ident, low))
        row = cur.fetchone()
        if row:
            row['table'] = 'users'
            return row
        if EMAIL_RE.match(low):
            cur.execute('SELECT id, name, email FROM staff WHERE LOWER(email) = %s AND active = 1 LIMIT 1', (low,))
            row = cur.fetchone()
            if row:
                row['table'] = 'staff'
                return row
    return None


def _acct_key(acct):
    return (acct['table'], acct['id'])


@app.route('/api/forgot/send-otp', methods=['POST'])
def forgot_send_otp():
    data = request.get_json(silent=True) or {}
    ident = clean(data.get('id'), 120)
    if not ident:
        return fail('Enter your Gmail or roll number')
    if too_many(f'fp-send-ip:{request.remote_addr}', 10, 3600):
        return fail('Too many requests. Please try again later.', 429)

    # Same answer whether or not the account exists, so this cannot be used to look up who has an account.
    generic = ok('If an account matches, an OTP has been sent to its registered email.')
    acct = _account_for_reset(ident)
    if not acct or not acct.get('email'):
        return generic

    _prune(_reset_otps)
    k = _acct_key(acct)
    prev = _reset_otps.get(k)
    if prev and time.time() - prev['sent'] < 30:
        return generic          # resend cooldown

    otp = str(secrets.randbelow(900000) + 100000)
    _reset_otps[k] = {'otp': otp, 'exp': time.time() + RESET_OTP_TTL, 'tries': 0, 'sent': time.time()}
    _reset_tokens.pop(k, None)
    send_email_async(acct['email'], 'CampusFix - Password Reset OTP',
                     f"Hello {acct.get('name') or 'there'},\n\n"
                     f"Your password reset OTP is: {otp}\n\nIt is valid for 5 minutes. "
                     f"If you did not ask for this, you can ignore this email - your password has not changed.")
    return generic


@app.route('/api/forgot/verify-otp', methods=['POST'])
def forgot_verify_otp():
    data = request.get_json(silent=True) or {}
    entered = clean(data.get('otp'), 10)
    if too_many(f'fp-verify-ip:{request.remote_addr}', 30, 3600):
        return fail('Too many attempts. Please try again later.', 429)
    acct = _account_for_reset(data.get('id'))
    k = _acct_key(acct) if acct else None
    rec = _reset_otps.get(k) if acct else None
    if not rec or time.time() > rec['exp']:
        if acct:
            _reset_otps.pop(k, None)
        return fail('OTP expired or not requested. Please request a new one.')
    rec['tries'] += 1
    if rec['tries'] > OTP_MAX_TRIES:
        _reset_otps.pop(k, None)
        return fail('Too many wrong attempts. Please request a new OTP.')
    if not hmac.compare_digest(rec['otp'], entered):
        return fail('Incorrect OTP - try again')
    _reset_otps.pop(k, None)
    token = secrets.token_urlsafe(32)
    _reset_tokens[k] = {'token': token, 'exp': time.time() + RESET_TOKEN_TTL}
    return ok(token=token)


@app.route('/api/forgot/reset', methods=['POST'])
def forgot_reset():
    data = request.get_json(silent=True) or {}
    token = clean(data.get('token'), 100)
    password = data.get('password') or ''
    if len(password) < 6 or len(password) > 128:
        return fail('Password must be 6 to 128 characters.')
    acct = _account_for_reset(data.get('id'))
    k = _acct_key(acct) if acct else None
    rec = _reset_tokens.get(k) if acct else None
    if not rec or time.time() > rec['exp'] or not hmac.compare_digest(rec['token'], token):
        return fail('Your reset session expired. Please start again.')
    with db(True) as (conn, cur):
        if acct['table'] == 'staff':     # choosing their own password also ends the "temporary password" state
            cur.execute('UPDATE staff SET password = %s, must_change_password = 0 WHERE id = %s',
                        (generate_password_hash(password), acct['id']))
        else:
            cur.execute('UPDATE users SET password_hash = %s WHERE id = %s',
                        (generate_password_hash(password), acct['id']))
        conn.commit()
    _reset_tokens.pop(k, None)
    _reset_otps.pop(k, None)
    if acct.get('email'):
        send_email_async(acct['email'], 'CampusFix - Your password was changed',
                         f"Hello {acct.get('name') or 'there'},\n\n"
                         f"Your CampusFix password was just changed. If this was not you, "
                         f"please contact the administrator immediately.")
    return ok('Password updated successfully!')


# ---------- signup / login ----------
@app.route('/signup', methods=['POST'])
def signup():
    as_json = request.is_json
    f = (request.get_json(silent=True) or {}) if as_json else request.form

    def err(msg, code):
        return fail(msg, code) if as_json else (msg, code)

    name = clean(f.get('name'), 100)
    roll = clean(f.get('roll_no'), 50)
    email = norm_email(f.get('email'))
    password = f.get('password') or ''
    course_year = f"{clean(f.get('course'), 60)} {clean(f.get('year'), 30)}".strip()

    if len(name) < 2 or not roll:
        return err('Name and roll number are required.', 400)
    if not EMAIL_RE.match(email):
        return err('Please enter a valid email address.', 400)
    if len(password) < 6 or len(password) > 128:
        return err('Password must be 6 to 128 characters.', 400)
    if REQUIRE_EMAIL_OTP and _verified.get(email, 0) < time.time():
        return err('Please verify your email with the OTP first.', 403)

    with db(True) as (conn, cur):
        cur.execute('SELECT id FROM users WHERE roll_number = %s OR LOWER(email) = %s LIMIT 1', (roll, email))
        if cur.fetchone():
            return err('An account with this roll number or email already exists.', 409)
        cur.execute("""INSERT INTO users (name, email, password_hash, role, roll_number, course_year)
                       VALUES (%s, %s, %s, 'student', %s, %s)""",
                    (name, email, generate_password_hash(password), roll, course_year))
        conn.commit()
    _verified.pop(email, None)
    return ok('Account created', redirect=url_for('index')) if as_json else redirect(url_for('index'))


def authenticate(login_id, password):
    """One login for everyone. Students/admins are looked up by roll number or email in `users`,
    staff by email in `staff`.  -> (kind, row, error)  kind: 'student' | 'admin' | 'staff'"""
    lid = login_id.lower()
    with db(True) as (conn, cur):
        cur.execute('SELECT * FROM users WHERE roll_number = %s OR LOWER(email) = %s LIMIT 1', (login_id, lid))
        user = cur.fetchone()
        if user:
            valid, upgrade = verify_password(user['password_hash'], password)
            if valid:
                if upgrade:  # old plain-text password -> store a hash
                    cur.execute('UPDATE users SET password_hash = %s WHERE id = %s',
                                (generate_password_hash(password), user['id']))
                    conn.commit()
                role = normalize_role(user['role'])
                if not role:
                    return None, None, ('Your account has no valid role. Please contact the administrator.', 403)
                return role, user, None
        if EMAIL_RE.match(lid):
            cur.execute('SELECT * FROM staff WHERE LOWER(email) = %s AND active = 1 LIMIT 1', (lid,))
            staff = cur.fetchone()
            if staff:
                valid, upgrade = verify_password(staff['password'], password)
                if valid:
                    if upgrade:
                        cur.execute('UPDATE staff SET password = %s WHERE id = %s',
                                    (generate_password_hash(password), staff['id']))
                        conn.commit()
                    return 'staff', staff, None
    return None, None, ('Invalid login ID or password.', 401)


@app.route('/login', methods=['POST'])
def login():
    as_json = request.is_json            # the login page sends JSON; a plain form POST still works
    data = (request.get_json(silent=True) if as_json else request.form) or {}
    login_id = clean(data.get('login_id') or data.get('email'), 120)
    password = data.get('password') or ''

    def err(msg, code):
        return fail(msg, code) if as_json else (msg, code)

    if not login_id or not password:
        return err('Please enter your login ID and password.', 400)
    key = f'{request.remote_addr}|{login_id.lower()}'
    if login_locked(key):
        return err('Too many failed attempts. Please try again in a few minutes.', 429)

    kind, row, error = authenticate(login_id, password)
    if error:
        if error[1] == 401:
            login_failed(key)
        return err(*error)

    session.clear()
    session.permanent = True
    if kind == 'staff':
        session.update(staff_id=row['id'], role='staff', name=row['name'], dept=row.get('dept'))
        target = url_for('staff_dashboard')
    else:
        session.update(user_id=row['id'], role=kind, name=row['name'])
        target = url_for('admin_dashboard' if kind == 'admin' else 'student_dashboard')
    return ok('Login successful!', redirect=target) if as_json else redirect(target)


@app.route('/staff-login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'GET':       # old URL: everyone logs in from the main page now
        return redirect(url_for('index'))
    return login()


# ======================================================================
# Student API
# ======================================================================
@app.route('/api/complaints', methods=['POST'])
@require_role('student')
def api_add_complaint():
    data = request.get_json(silent=True) or {}
    title = clean(data.get('title'), 200)
    description = clean(data.get('details') or data.get('description'), 3000)
    location = clean(data.get('address') or data.get('location') or 'Campus', 255)
    category = clean(data.get('category'), 40) or 'Other'
    client_cid = clean(data.get('cid'), 64) or None
    priority = PRIORITY_TO_DB.get(str(data.get('priority', 'normal')).lower(), 'Medium')
    if priority == 'Low':
        priority = 'Medium'  # students choose Normal / Important / Urgent only

    if not title or not description:
        return fail('Title and description are required')
    if category not in CATEGORIES:
        category = 'Other'

    photo = None
    if data.get('photo'):
        chk = check_data_url(data['photo'], MAX_COMPLAINT_PHOTO)
        if not chk:
            return fail('Photo must be a JPG, PNG or WebP image under 3 MB')
        photo = chk[0]

    student_id = session['user_id']
    with db(True) as (conn, cur):
        if client_cid:  # the phone may retry a request that already succeeded
            cur.execute('SELECT id FROM complaints WHERE student_id = %s AND client_cid = %s LIMIT 1',
                        (student_id, client_cid))
            dup = cur.fetchone()
            if dup:
                return ok('Complaint registered successfully!', id=cf_id(dup['id']))
        try:
            cur.execute("""INSERT INTO complaints
                             (student_id, title, description, location, category, priority, status, photo, client_cid)
                           VALUES (%s, %s, %s, %s, %s, %s, 'Pending', %s, %s)""",
                        (student_id, title, description, location, category, priority, photo, client_cid))
        except Exception:
            conn.rollback()
            if client_cid:   # the same request arrived twice at once: return the first one
                cur.execute('SELECT id FROM complaints WHERE student_id = %s AND client_cid = %s LIMIT 1',
                            (student_id, client_cid))
                dup = cur.fetchone()
                if dup:
                    return ok('Complaint registered successfully!', id=cf_id(dup['id']))
            raise
        new_id = cur.lastrowid
        add_log(cur, new_id, 'Complaint submitted', 'submitted')
        conn.commit()
    return ok('Complaint registered successfully!', id=cf_id(new_id))


@app.route('/api/complaints', methods=['GET'])
@require_role('student')
def api_get_complaints():
    with db(True) as (conn, cur):
        cur.execute(f'SELECT {COMPLAINT_COLS} FROM complaints c WHERE c.student_id = %s '
                    'ORDER BY c.created_at DESC, c.id DESC', (session['user_id'],))
        rows = cur.fetchall()
        logs = fetch_logs(cur, [r['id'] for r in rows])
    return jsonify([serialize_complaint(r, logs.get(r['id'])) for r in rows])


def _own_complaint(cur, cid):
    """-> (numeric_id, row, error_response). Only the owner's complaint is returned."""
    num = parse_cid(cid)
    if num is None:
        return None, None, fail('Invalid complaint ID', 400)
    cur.execute('SELECT id, status FROM complaints WHERE id = %s AND student_id = %s',
                (num, session['user_id']))
    return num, cur.fetchone(), None


@app.route('/api/complaints/<string:cid>', methods=['DELETE'])
@require_role('student')
def api_delete_specific_complaint(cid):
    if str(cid).upper().startswith('TMP-'):      # never reached the server -> nothing to delete
        return ok('Nothing to delete on the server')
    with db(True) as (conn, cur):
        num, row, err = _own_complaint(cur, cid)
        if err:
            return err
        if not row:                                 # already gone (deleted on another device)
            return ok('Already removed')
        if status_ui(row['status']) != 'submitted':
            return fail('Cannot delete a complaint once it is under review', 400)
        cur.execute('DELETE FROM complaint_log WHERE complaint_id = %s', (num,))
        cur.execute('DELETE FROM complaints WHERE id = %s', (num,))
        conn.commit()
    return ok('Complaint deleted successfully!')


@app.route('/api/complaints/<string:cid>/reopen', methods=['POST'])
@require_role('student')
def api_reopen_complaint(cid):
    with db(True) as (conn, cur):
        num, row, err = _own_complaint(cur, cid)
        if err:
            return err
        if not row:
            return fail('Complaint not found', 404)
        if status_ui(row['status']) != 'resolved':
            return fail('Only resolved complaints can be reopened', 400)
        cur.execute("""UPDATE complaints SET status = 'In Progress', resolved_at = NULL, rating = NULL
                       WHERE id = %s""", (num,))
        add_log(cur, num, 'Reopened by student', 'review')
        conn.commit()
    return ok('Complaint reopened')


@app.route('/api/complaints/<string:cid>/rating', methods=['POST'])
@require_role('student')
def api_rate_complaint(cid):
    data = request.get_json(silent=True) or {}
    try:
        rating = int(data.get('rating'))
    except (TypeError, ValueError):
        return fail('Rating must be a number from 1 to 5')
    if not 1 <= rating <= 5:
        return fail('Rating must be a number from 1 to 5')
    with db(True) as (conn, cur):
        num, row, err = _own_complaint(cur, cid)
        if err:
            return err
        if not row:
            return fail('Complaint not found', 404)
        if status_ui(row['status']) != 'resolved':
            return fail('You can rate a complaint after it is resolved', 400)
        cur.execute('UPDATE complaints SET rating = %s WHERE id = %s', (rating, num))
        conn.commit()
    return ok('Thanks for your feedback!')


# ---------- student profile ----------
@app.route('/api/user', methods=['GET'])
@require_role('student', 'admin')
def api_get_user():
    with db(True) as (conn, cur):
        cur.execute("""SELECT name, email, roll_number, course_year, profile_photo, phone, Residence, room_no
                       FROM users WHERE id = %s""", (session['user_id'],))
        row = cur.fetchone()
    if not row:
        return fail('User not found', 404)
    course_year = row.get('course_year') or ''
    m = YEAR_RE.match(course_year)
    course, year = (m.group(1).strip(), m.group(2)) if m else (course_year.strip(), '')
    return jsonify({
        'name': row.get('name') or '',
        'gmail': row.get('email') or '',
        'roll': row.get('roll_number') or '',
        'course': course,
        'year': year,
        'hostel': row.get('Residence') or 'Day Scholar',
        'room': row.get('room_no') or '',
        'phone': row.get('phone') or '',
        'photo': row.get('profile_photo') or '',
    })


@app.route('/api/update-profile', methods=['POST'])
@require_role('student')
def update_profile():
    data = request.get_json(silent=True) or request.form
    name = clean(data.get('name'), 100)
    roll = clean(data.get('roll'), 50)
    course_year = f"{clean(data.get('course'), 60)} {clean(data.get('year'), 30)}".strip()
    phone = clean(data.get('phone'), 15)
    residence = 'Hostel' if clean(data.get('hostel'), 50) == 'Hostel' else 'Day Scholar'
    room = clean(data.get('room'), 30) if residence == 'Hostel' else ''

    if len(name) < 2:
        return fail('Name is required')
    if not roll:
        return fail('Roll number is required')
    if not valid_phone(phone):
        return fail('Phone number must be 10 digits')

    uid = session['user_id']
    with db(True) as (conn, cur):
        cur.execute('SELECT id FROM users WHERE roll_number = %s AND id <> %s LIMIT 1', (roll, uid))
        if cur.fetchone():
            return fail('This roll number belongs to another account', 409)
        cur.execute("""UPDATE users SET name = %s, roll_number = %s, course_year = %s, phone = %s,
                              Residence = %s, room_no = %s WHERE id = %s""",
                    (name, roll, course_year, phone, residence, room, uid))
        conn.commit()
    session['name'] = name
    return ok('Profile updated successfully!')


@app.route('/api/update-photo', methods=['POST'])
@require_role('student', 'admin')
def update_photo():
    data = request.get_json(silent=True) or {}
    photo = data.get('photo')
    value = None
    if photo:
        chk = check_data_url(photo, MAX_PROFILE_PHOTO)
        if not chk:
            return fail('Photo must be a JPG, PNG or WebP image under 1 MB')
        value = chk[0]
    with db() as (conn, cur):
        cur.execute('UPDATE users SET profile_photo = %s WHERE id = %s', (value, session['user_id']))
        conn.commit()
    return ok('Photo updated successfully!')


@app.route('/api/change-password', methods=['POST'])
@require_role('student', 'admin')
def api_change_password():
    data = request.get_json(silent=True) or {}
    old, new = data.get('old') or '', data.get('new') or ''
    key = f"userpw:{session['user_id']}"
    if login_locked(key):
        return fail('Too many wrong attempts. Please try again in a few minutes.', 429)
    if not 6 <= len(new) <= 128:
        return fail('New password must be 6 to 128 characters')
    if new == old:
        return fail('New password must be different')
    with db(True) as (conn, cur):
        cur.execute('SELECT password_hash FROM users WHERE id = %s', (session['user_id'],))
        row = cur.fetchone()
        if not row:
            return fail('User not found', 404)
        if not verify_password(row['password_hash'], old)[0]:
            login_failed(key)
            return fail('Current password is incorrect')
        cur.execute('UPDATE users SET password_hash = %s WHERE id = %s',
                    (generate_password_hash(new), session['user_id']))
        conn.commit()
    return ok('Password changed')


@app.route('/api/notifications', methods=['GET'])
@require_role('student')
def api_notifications():
    with db(True) as (conn, cur):
        cur.execute('SELECT id, complaint_id, title, message, is_read, created_at FROM user_notifications '
                    'WHERE user_id = %s ORDER BY id DESC LIMIT 50', (session['user_id'],))
        rows = cur.fetchall()
    return jsonify([{'id': r['id'], 'cid': cf_id(r['complaint_id']) if r['complaint_id'] else None,
                     'title': r['title'], 'text': r['message'], 'read': bool(r['is_read']),
                     'ts': to_ms(r['created_at']) or 0} for r in rows])


@app.route('/api/notifications/read', methods=['POST'])
@require_role('student')
def api_notifications_read():
    data = request.get_json(silent=True) or {}
    with db() as (conn, cur):
        if data.get('all'):
            cur.execute('UPDATE user_notifications SET is_read = 1 WHERE user_id = %s', (session['user_id'],))
        else:
            ids = [int(i) for i in (data.get('ids') or []) if str(i).isdigit()][:100]
            if ids:
                marks = ','.join(['%s'] * len(ids))
                cur.execute(f'UPDATE user_notifications SET is_read = 1 WHERE user_id = %s AND id IN ({marks})',
                            (session['user_id'], *ids))
        conn.commit()
    return ok()


@app.route('/api/notifications', methods=['DELETE'])
@require_role('student')
def api_notifications_clear():
    with db() as (conn, cur):
        cur.execute('DELETE FROM user_notifications WHERE user_id = %s', (session['user_id'],))
        conn.commit()
    return ok()


@app.route('/api/photos/<string:kind>/<int:num>')
def api_photo(kind, num):
    col = {'complaint': 'photo', 'resolution': 'resolution_photo'}.get(kind)
    role = session.get('role')
    if not col or role not in ('student', 'admin', 'staff'):
        return fail('Not found', 404)
    with db(True) as (conn, cur):
        cur.execute(f'SELECT student_id, assigned_to, {col} AS img FROM complaints WHERE id = %s', (num,))
        row = cur.fetchone()
        allowed = False
        if row and role == 'admin':
            allowed = True
        elif row and role == 'student':
            allowed = row['student_id'] == session.get('user_id')
        elif row and role == 'staff':
            cur.execute('SELECT 1 FROM staff WHERE id = %s AND active = 1', (session.get('staff_id'),))
            allowed = row['assigned_to'] == session.get('staff_id') and cur.fetchone() is not None
    if not row or not allowed or not row['img']:
        return fail('Not found', 404)
    try:
        head, _, b64 = row['img'].partition(',')
        mime = head[5:head.index(';')]
        raw = base64.b64decode(b64)
    except Exception:
        return fail('Not found', 404)
    resp = Response(raw, mimetype=mime)
    resp.headers['Cache-Control'] = 'private, max-age=86400'
    return resp


@app.route('/api/geocode', methods=['GET'])
@require_role('student')
def api_geocode():
    """Reverse geocoding proxy used by the 'use my location' button."""
    try:
        lat, lon = float(request.args.get('lat')), float(request.args.get('lon'))
    except (TypeError, ValueError):
        return fail('Invalid coordinates')
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return fail('Invalid coordinates')
    if too_many(f'geo:{session["user_id"]}', 20, 60):
        return fail('Too many requests', 429)
    url = 'https://nominatim.openstreetmap.org/reverse?' + urlparse.urlencode(
        {'format': 'jsonv2', 'lat': lat, 'lon': lon})
    try:
        req = urlrequest.Request(url, headers={'User-Agent': 'CampusFix/1.0'})
        with urlrequest.urlopen(req, timeout=6) as r:
            body = json.loads(r.read().decode('utf-8'))
        return jsonify({'display_name': body.get('display_name', '')})
    except Exception as e:
        app.logger.warning('Geocode failed: %s', e)
        return fail('Could not look up the address', 502)


# ======================================================================
# Admin API: complaints
# ======================================================================
@app.route('/api/hod/complaints', methods=['GET'])
@require_role('admin')
def api_hod_get_complaints():
    with db(True) as (conn, cur):
        cur.execute(f"""SELECT {COMPLAINT_COLS}, u.name AS student_name, u.email AS student_email,
                              u.phone AS student_phone
                       FROM complaints c LEFT JOIN users u ON c.student_id = u.id
                       ORDER BY c.created_at DESC, c.id DESC""")
        rows = cur.fetchall()
        logs = fetch_logs(cur)
    return jsonify([serialize_complaint(r, logs.get(r['id']), admin=True) for r in rows])


@app.route('/api/hod/complaints/<string:cid>', methods=['PATCH', 'POST'])
@require_role('admin')
def api_hod_update_complaint(cid):
    num = parse_cid(cid)
    if num is None:
        return fail('Invalid complaint ID')
    data = request.get_json(silent=True) or {}

    sets, params, logs = [], [], []
    notes, mail = [], None

    if 'priority' in data:
        pr = PRIORITY_TO_DB.get(str(data['priority']).lower())
        if not pr:
            return fail('Invalid priority')
        sets.append('priority = %s'); params.append(pr)
        logs.append((f'Priority set to {pr}', None))
        notes.append(('Priority updated', f'{cf_id(num)} priority was set to {pr}.'))

    new_status = None
    if 'status' in data:
        new_status = str(data['status']).lower()
        if new_status == 'resolved':
            return fail('Use the Resolve option - a fix photo and report are required')
        if new_status not in ('submitted', 'review'):
            return fail('Invalid status')

    with db(True) as (conn, cur):
        cur.execute('SELECT id, status FROM complaints WHERE id = %s', (num,))
        row = cur.fetchone()
        if not row:
            return fail('Complaint not found', 404)

        if new_status:
            was_resolved = status_ui(row['status']) == 'resolved'
            sets.append('status = %s'); params.append(STATUS_TO_DB[new_status])
            if was_resolved:
                sets += ['resolved_at = NULL', 'resolution_note = NULL', 'resolution_photo = NULL',
                         'resolved_by = NULL', 'notified_at = NULL', 'rating = NULL']
            msg = ('Reopened' if was_resolved else
                   'Marked Under Review' if new_status == 'review' else 'Marked Pending')
            logs.append((msg, new_status))
            title = 'Complaint reopened' if was_resolved else 'Under review' if new_status == 'review' else 'Marked pending'
            notes.append((title, f'{cf_id(num)} - {msg.lower()}.'))
            if new_status == 'review' or was_resolved:
                state = 'reopened and is back under review' if was_resolved else 'now under review'
                mail = (f'CampusFix - Your complaint {cf_id(num)} is {title.lower()}',
                        f'Your complaint "{{title}}" ({cf_id(num)}) is {state}.\n\nWe will keep you updated.')

        if 'assignedTo' in data:
            raw = data['assignedTo']
            if raw in (None, '', 0, '0'):
                sets.append('assigned_to = NULL')
                logs.append(('Unassigned', None))
            else:
                try:
                    sid = int(raw)
                except (TypeError, ValueError):
                    return fail('Invalid staff ID')
                cur.execute('SELECT name FROM staff WHERE id = %s AND active = 1', (sid,))
                st = cur.fetchone()
                if not st:
                    return fail('Staff member not found or disabled', 404)
                sets.append('assigned_to = %s'); params.append(sid)
                logs.append((f"Assigned to {st['name']}", None))
                notes.append(('Staff assigned', f"{cf_id(num)} was assigned to {st['name']}."))

        if not sets:
            return fail('Nothing to update')
        cur.execute(f"UPDATE complaints SET {', '.join(sets)} WHERE id = %s", tuple(params) + (num,))
        for msg, kind in logs:
            add_log(cur, num, msg, kind)
        for title, message in notes:
            notify(cur, num, title, message)
        conn.commit()
    if mail:
        mail_student(num, *mail)
    return ok('Complaint updated successfully!')


@app.route('/api/hod/complaints/<string:cid>/resolve', methods=['POST'])
@require_role('admin')
def api_hod_resolve_complaint(cid):
    num = parse_cid(cid)
    if num is None:
        return fail('Invalid complaint ID')

    # accepts multipart (fix_photo file + report) or JSON ({photo: dataURL, report}); the photo is optional
    photo_url = raw_photo = sub = None
    f = request.files.get('fix_photo')
    if f:
        res = check_image_bytes(f.read(), MAX_COMPLAINT_PHOTO)
        if not res:
            return fail('Photo must be a JPG, PNG or WebP image under 3 MB')
        photo_url, sub = res
        raw_photo = base64.b64decode(photo_url.split(',', 1)[1])
        report = clean(request.form.get('report'), 3000)
    else:
        data = request.get_json(silent=True) or {}
        given = data.get('photo') or data.get('fix_photo')
        if given:
            chk = check_data_url(given, MAX_COMPLAINT_PHOTO)
            if not chk:
                return fail('Photo must be a JPG, PNG or WebP image under 3 MB')
            photo_url, raw_photo, sub = chk
        report = clean(data.get('report'), 3000)

    if len(report) < MIN_REPORT:
        return fail(f'Resolution report must be at least {MIN_REPORT} characters')

    admin_name = session.get('name') or 'Admin'
    with db(True) as (conn, cur):
        cur.execute("""SELECT c.id, c.title, u.name AS student_name, u.email AS student_email
                       FROM complaints c LEFT JOIN users u ON c.student_id = u.id WHERE c.id = %s""", (num,))
        row = cur.fetchone()
        if not row:
            return fail('Complaint not found', 404)
        cur.execute("""UPDATE complaints SET status = 'Resolved', resolved_at = CURRENT_TIMESTAMP,
                              resolution_note = %s, resolution_photo = %s, resolved_by = %s,
                              notified_at = CURRENT_TIMESTAMP
                       WHERE id = %s""", (report, photo_url, admin_name, num))
        add_log(cur, num, 'Resolved with fix photo & report', 'resolved')
        notify(cur, num, 'Complaint resolved', f'{cf_id(num)} - "{row["title"]}" was resolved by {admin_name}.')
        conn.commit()

    if row.get('student_email') and SMTP_EMAIL and SMTP_APP_PASSWORD:
        send_email_async(
            row['student_email'],
            f"CampusFix - Your complaint {cf_id(num)} is resolved",
            f"Hello {row.get('student_name') or 'Student'},\n\n"
            f"Your complaint \"{row['title']}\" ({cf_id(num)}) has been resolved by {admin_name}.\n\n"
            f"Resolution report:\n{report}\n\n"
            f"{'The photo of the completed fix is attached. ' if raw_photo else ''}If the problem is not fixed, "
            f"you can reopen the complaint from your dashboard.",
            attachment=(raw_photo, sub) if raw_photo else None)
    return ok('Complaint resolved and the student was notified.')


@app.route('/api/hod/complaints/<string:cid>', methods=['DELETE'])
@require_role('admin')
def api_hod_delete_complaint(cid):
    num = parse_cid(cid)
    if num is None:
        return fail('Invalid complaint ID')
    with db() as (conn, cur):
        cur.execute('DELETE FROM complaint_log WHERE complaint_id = %s', (num,))
        cur.execute('DELETE FROM complaints WHERE id = %s', (num,))
        deleted = cur.rowcount
        conn.commit()
    if not deleted:
        return fail('Complaint not found', 404)
    return ok('Complaint deleted')


# ======================================================================
# Admin API: profile
# ======================================================================
@app.route('/api/hod/profile', methods=['GET'])
@require_role('admin')
def api_hod_get_profile():
    with db(True) as (conn, cur):
        cur.execute('SELECT name, email, phone, profile_photo, emp_id, dept FROM users WHERE id = %s',
                    (session['user_id'],))
        row = cur.fetchone()
    if not row:
        return fail('User not found', 404)
    return jsonify({'name': row.get('name') or '', 'email': row.get('email') or '',
                    'phone': row.get('phone') or '', 'role': 'Admin',
                    'photo': row.get('profile_photo') or '', 'empId': row.get('emp_id') or '',
                    'dept': row.get('dept') or DEPTS[-1]})


@app.route('/api/hod/update-profile', methods=['POST'])
@require_role('admin')
def update_hod_profile():
    data = request.get_json(silent=True) or {}
    name = clean(data.get('name'), 100)
    email = norm_email(data.get('email'))
    phone = clean(data.get('phone'), 15)
    emp_id = clean(data.get('empId'), 40)
    dept = clean(data.get('dept'), 80) or DEPTS[-1]

    if len(name) < 2:
        return fail('Name is required')
    if email and not EMAIL_RE.match(email):
        return fail('Invalid email address')
    if not valid_phone(phone):
        return fail('Phone number must be 10 digits')
    if dept not in DEPTS:
        return fail('Invalid department')

    uid = session['user_id']
    with db(True) as (conn, cur):
        if email:
            cur.execute('SELECT id FROM users WHERE LOWER(email) = %s AND id <> %s LIMIT 1', (email, uid))
            if cur.fetchone():
                return fail('This email belongs to another account', 409)
            cur.execute('UPDATE users SET email = %s WHERE id = %s', (email, uid))
        cur.execute('UPDATE users SET name = %s, phone = %s, emp_id = %s, dept = %s WHERE id = %s',
                    (name, phone, emp_id, dept, uid))
        conn.commit()
    session['name'] = name
    return ok('Profile updated successfully!')


# ======================================================================
# Admin API: staff management (passwords are generated + hashed here)
# ======================================================================
def _validate_staff(data, partial=False):
    """-> (clean_dict, error). Only whitelisted fields are returned."""
    out = {}
    if not partial or 'name' in data:
        out['name'] = clean(data.get('name'), 100)
        if len(out['name']) < 2:
            return None, 'Name is required'
    if not partial or 'email' in data:
        out['email'] = norm_email(data.get('email'))
        if not EMAIL_RE.match(out['email']):
            return None, 'Enter a valid email'
    if not partial or 'dept' in data:
        out['dept'] = clean(data.get('dept'), 80)
        if out['dept'] not in DEPTS:
            return None, 'Invalid department'
    if not partial or 'role' in data:
        out['role'] = clean(data.get('role'), 60)
        if out['role'] not in STAFF_ROLES:
            return None, 'Invalid role'
    if not partial or 'phone' in data:
        out['phone'] = clean(data.get('phone'), 15)
        if not valid_phone(out['phone']):
            return None, 'Phone number must be 10 digits'
    if 'active' in data:
        out['active'] = 1 if data.get('active') else 0
    return out, None


@app.route('/api/hod/staff', methods=['GET'])
@require_role('admin')
def api_hod_staff_list():
    with db(True) as (conn, cur):
        cur.execute('SELECT id, name, email, dept, role, phone, active, created_at FROM staff '
                    'ORDER BY created_at DESC, id DESC')
        rows = cur.fetchall()
    return jsonify([serialize_staff(r) for r in rows])


def email_staff_password(name, email, password, created):
    """Send the temporary password by email only. -> True if the mail went out."""
    try:
        send_email(
            email,
            'CampusFix - Your Staff Account Has Been Created' if created else 'CampusFix - Your Password Was Reset',
            f"Hello {name},\n\n"
            + ("Your staff account has been created on CampusFix.\n\n" if created
               else "Your CampusFix password was reset by the administrator.\n\n")
            + f"Login Email: {email}\n"
            f"Temporary Password: {password}\n\n"
            f"Log in at {request.host_url} - you will be asked to choose a new password "
            f"straight away, and the temporary one stops working after that.")
        return True
    except Exception as e:
        app.logger.warning('Staff password email failed: %s', e)
        return False


@app.route('/api/hod/staff', methods=['POST'])
@require_role('admin')
def api_hod_staff_create():
    vals, err = _validate_staff(request.get_json(silent=True) or {})
    if err:
        return fail(err)
    password = gen_password()
    with db(True) as (conn, cur):
        cur.execute('SELECT id FROM staff WHERE LOWER(email) = %s LIMIT 1', (vals['email'],))
        if cur.fetchone():
            return fail('A staff account with this email already exists', 409)
        try:
            cur.execute("""INSERT INTO staff (name, email, dept, role, phone, password, active,
                                              must_change_password, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, 1, 1, CURRENT_TIMESTAMP)""",
                        (vals['name'], vals['email'], vals['dept'], vals['role'], vals['phone'],
                         generate_password_hash(password)))
            new_id = cur.lastrowid
            conn.commit()
        except Exception as e:   # admin-only screen: show the real reason so it can be fixed
            app.logger.exception('Staff insert failed')
            reason = str(getattr(e, 'msg', None) or e)[:160]
            return fail(f'Could not create the account: {reason}', 500)

    # The password is never sent back to the browser - it only goes to the staff member's inbox.
    emailed = email_staff_password(vals['name'], vals['email'], password, created=True)
    return ok('Staff registered successfully!' if emailed else
              'Account created, but the email could not be sent. Fix the email settings and use Reset Pass.',
              id=str(new_id), emailed=emailed)


@app.route('/api/hod/staff/<int:sid>', methods=['PATCH', 'POST'])
@require_role('admin')
def api_hod_staff_update(sid):
    vals, err = _validate_staff(request.get_json(silent=True) or {}, partial=True)
    if err:
        return fail(err)
    if not vals:
        return fail('Nothing to update')
    with db(True) as (conn, cur):
        cur.execute('SELECT id FROM staff WHERE id = %s', (sid,))
        if not cur.fetchone():
            return fail('Staff member not found', 404)
        if 'email' in vals:
            cur.execute('SELECT id FROM staff WHERE LOWER(email) = %s AND id <> %s LIMIT 1', (vals['email'], sid))
            if cur.fetchone():
                return fail('A staff account with this email already exists', 409)
        cols = [c for c in ('name', 'email', 'dept', 'role', 'phone', 'active') if c in vals]  # fixed whitelist
        cur.execute(f"UPDATE staff SET {', '.join(c + ' = %s' for c in cols)} WHERE id = %s",
                    tuple(vals[c] for c in cols) + (sid,))
        conn.commit()
    return ok('Staff details updated')


@app.route('/api/hod/staff/<int:sid>/reset-password', methods=['POST'])
@require_role('admin')
def api_hod_staff_reset(sid):
    password = gen_password()
    with db(True) as (conn, cur):
        cur.execute('SELECT name, email FROM staff WHERE id = %s', (sid,))
        st = cur.fetchone()
        if not st:
            return fail('Staff member not found', 404)
        cur.execute('UPDATE staff SET password = %s, must_change_password = 1 WHERE id = %s',
                    (generate_password_hash(password), sid))
        conn.commit()
    emailed = email_staff_password(st['name'], st['email'], password, created=False)
    return ok('Password reset and emailed to the staff member.' if emailed else
              'Password reset, but the email could not be sent. Fix the email settings and reset again.',
              emailed=emailed)


@app.route('/api/hod/staff/<int:sid>', methods=['DELETE'])
@require_role('admin')
def api_hod_staff_delete(sid):
    with db() as (conn, cur):
        cur.execute('UPDATE complaints SET assigned_to = NULL WHERE assigned_to = %s', (sid,))
        cur.execute('DELETE FROM staff WHERE id = %s', (sid,))
        deleted = cur.rowcount
        conn.commit()
    if not deleted:
        return fail('Staff member not found', 404)
    return ok('Staff account deleted')


# ======================================================================
# Staff API
# ======================================================================
STAFF_ACTIONS = {'start', 'note', 'escalate', 'resolve', 'reopen'}
MIN_STAFF_NOTE = 10
MIN_PASSWORD = 8


@app.route('/api/staff/me', methods=['GET'])
@staff_required()
def api_staff_me():
    me = g.staff
    with db(True) as (conn, cur):
        cur.execute("""SELECT assigned_to AS id, COUNT(*) AS n FROM complaints
                       WHERE status = 'Resolved' AND assigned_to IS NOT NULL GROUP BY assigned_to""")
        counts = {r['id']: r['n'] for r in cur.fetchall()}
        cur.execute('SELECT id FROM staff WHERE active = 1')
        ids = [r['id'] for r in cur.fetchall()]
    mine = counts.get(me['id'], 0)
    d = serialize_staff(me)
    d.update(photo=me.get('profile_photo') or '', teamSize=len(ids),
             rank=1 + sum(1 for i in ids if counts.get(i, 0) > mine),
             mustChange=bool(me.get('must_change_password')))
    return jsonify(d)


@app.route('/api/staff/complaints', methods=['GET'])
@staff_required()
def api_staff_get_complaints():
    sid = g.staff['id']
    with db(True) as (conn, cur):
        cur.execute(f"""SELECT {COMPLAINT_COLS}, u.name AS student_name, u.email AS student_email,
                              u.phone AS student_phone
                       FROM complaints c LEFT JOIN users u ON c.student_id = u.id
                       WHERE c.assigned_to = %s ORDER BY c.created_at DESC, c.id DESC""", (sid,))
        rows = cur.fetchall()
        logs = fetch_logs(cur, [r['id'] for r in rows])
    out = []
    for r in rows:
        d = serialize_complaint(r, logs.get(r['id']), admin=True)
        d['resolutionNote'] = r.get('resolution_note') or ''
        d['resolutionPhoto'] = resolution_photo_url(r)
        d.pop('studentEmail', None)   # staff only need the phone number to reach the reporter
        out.append(d)
    return jsonify(out)


@app.route('/api/staff/complaints/<string:cid>/<string:action>', methods=['POST'])
@staff_required()
def api_staff_action(cid, action):
    num = parse_cid(cid)
    if num is None or action not in STAFF_ACTIONS:
        return fail('Invalid request')
    data = request.get_json(silent=True) or {}
    note = clean(data.get('note'), 3000)
    sid, sname = g.staff['id'], g.staff['name']
    mail = None

    if action == 'note' and len(note) < 3:
        return fail('Please write an update first')
    if action == 'resolve' and len(note) < MIN_STAFF_NOTE:
        return fail(f'Resolution note must be at least {MIN_STAFF_NOTE} characters')
    photo_url = raw = sub = None
    if action == 'resolve' and data.get('photo'):
        chk = check_data_url(data['photo'], MAX_COMPLAINT_PHOTO)
        if not chk:
            return fail('Photo must be a JPG, PNG or WebP image under 3 MB')
        photo_url, raw, sub = chk

    with db(True) as (conn, cur):
        cur.execute("""SELECT c.id, c.title, c.status, u.name AS student_name, u.email AS student_email
                       FROM complaints c LEFT JOIN users u ON c.student_id = u.id
                       WHERE c.id = %s AND c.assigned_to = %s FOR UPDATE""", (num, sid))
        row = cur.fetchone()
        if not row:
            return fail('Complaint not found or not assigned to you', 404)
        st = status_ui(row['status'])

        if action == 'start':
            if st != 'submitted':
                return fail('Work can only be started on a pending complaint')
            cur.execute("UPDATE complaints SET status = 'In Progress' WHERE id = %s", (num,))
            add_log(cur, num, f'Work started by {sname}', 'review')
            notify(cur, num, 'Work started', f'{cf_id(num)} - {sname} has started working on your complaint.')
            mail = (f'CampusFix - Work started on your complaint {cf_id(num)}',
                    f'{sname} has started working on your complaint "{{title}}" ({cf_id(num)}).')
        elif action == 'note':
            if st == 'resolved':
                return fail('This complaint is already resolved')
            add_log(cur, num, f'{sname}: {note}')
            notify(cur, num, 'Update from staff', f'{cf_id(num)} - {sname}: {note}')
        elif action == 'escalate':
            if st == 'resolved':
                return fail('This complaint is already resolved')
            cur.execute('UPDATE complaints SET escalated = 1 WHERE id = %s', (num,))
            add_log(cur, num, f'Escalated to HOD by {sname}')
        elif action == 'resolve':
            if st != 'review':
                return fail('Start work on the complaint before resolving it')
            cur.execute("""UPDATE complaints SET status = 'Resolved', resolved_at = CURRENT_TIMESTAMP,
                                  resolution_note = %s, resolution_photo = %s, resolved_by = %s,
                                  notified_at = CURRENT_TIMESTAMP WHERE id = %s""",
                        (note, photo_url, sname, num))
            add_log(cur, num, f'Resolved by {sname}', 'resolved')
            notify(cur, num, 'Complaint resolved', f'{cf_id(num)} - "{row["title"]}" was resolved by {sname}.')
        else:  # reopen
            if st != 'resolved':
                return fail('Only resolved complaints can be reopened')
            cur.execute("""UPDATE complaints SET status = 'In Progress', resolved_at = NULL, resolution_note = NULL,
                                  resolution_photo = NULL, resolved_by = NULL, notified_at = NULL, rating = NULL
                           WHERE id = %s""", (num,))
            add_log(cur, num, f'Reopened by {sname}', 'review')
            notify(cur, num, 'Complaint reopened', f'{cf_id(num)} is back under review.')
            mail = (f'CampusFix - Your complaint {cf_id(num)} was reopened',
                    f'Your complaint "{{title}}" ({cf_id(num)}) was reopened by {sname} and is back under review.')
        conn.commit()

    if mail:
        mail_student(num, *mail)
    if action == 'resolve' and row.get('student_email') and SMTP_EMAIL and SMTP_APP_PASSWORD:
        send_email_async(
            row['student_email'],
            f"CampusFix - Your complaint {cf_id(num)} is resolved",
            f"Hello {row.get('student_name') or 'Student'},\n\n"
            f"Your complaint \"{row['title']}\" ({cf_id(num)}) has been resolved by {sname}.\n\n"
            f"Resolution note:\n{note}\n\n"
            f"If the problem is not fixed, you can reopen the complaint from your dashboard.",
            attachment=(raw, sub) if raw else None)
    return ok('Done')


@app.route('/api/staff/update-profile', methods=['POST'])
@staff_required()
def api_staff_update_profile():
    data = request.get_json(silent=True) or {}
    name = clean(data.get('name'), 100)
    phone = clean(data.get('phone'), 15)
    if len(name) < 2:
        return fail('Name is required')
    if not valid_phone(phone):
        return fail('Phone number must be 10 digits')
    with db() as (conn, cur):   # department, role and email are managed by the HOD
        cur.execute('UPDATE staff SET name = %s, phone = %s WHERE id = %s', (name, phone, g.staff['id']))
        conn.commit()
    session['name'] = name
    return ok('Profile updated')


@app.route('/api/staff/update-photo', methods=['POST'])
@staff_required()
def api_staff_update_photo():
    photo = (request.get_json(silent=True) or {}).get('photo')
    value = None
    if photo:
        chk = check_data_url(photo, MAX_PROFILE_PHOTO)
        if not chk:
            return fail('Photo must be a JPG, PNG or WebP image under 1 MB')
        value = chk[0]
    with db() as (conn, cur):
        cur.execute('UPDATE staff SET profile_photo = %s WHERE id = %s', (value, g.staff['id']))
        conn.commit()
    return ok('Photo updated')


@app.route('/api/staff/change-password', methods=['POST'])
@staff_required()
def api_staff_change_password():
    data = request.get_json(silent=True) or {}
    old, new = data.get('old') or '', data.get('new') or ''
    key = f"staffpw:{g.staff['id']}"
    if login_locked(key):
        return fail('Too many wrong attempts. Please try again in a few minutes.', 429)
    if not verify_password(g.staff['password'], old)[0]:
        login_failed(key)
        return fail('Current password is incorrect', 400)
    if not MIN_PASSWORD <= len(new) <= 128:
        return fail(f'New password must be {MIN_PASSWORD} to 128 characters')
    if new == old:
        return fail('New password must be different')
    with db() as (conn, cur):
        cur.execute('UPDATE staff SET password = %s, must_change_password = 0 WHERE id = %s',
                    (generate_password_hash(new), g.staff['id']))
        conn.commit()
    return ok('Password changed')


if __name__ == '__main__':
    app.run(debug=env_flag('FLASK_DEBUG'))