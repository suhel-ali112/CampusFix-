import os
import sys
import threading
import time
import tempfile

import mysql.connector
from mysql.connector import Error, pooling
from mysql.connector.errors import PoolError
from dotenv import load_dotenv

load_dotenv()

_REQUIRED = ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
_pool = None
_pool_lock = threading.Lock()



def _ssl_options():
    ca_content = os.getenv("DB_SSL_CA_CONTENT", "").strip()

    if ca_content:
        import tempfile

        ca_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".pem",
            delete=False,
            encoding="utf-8",
        )
        ca_file.write(ca_content)
        ca_file.close()

        return {
            "ssl_ca": ca_file.name,
            "ssl_verify_cert": True,
        }

    ca_path = os.getenv("DB_SSL_CA", "").strip()

    if ca_path:
        ca_path = os.path.abspath(ca_path)

        if not os.path.isfile(ca_path):
            raise FileNotFoundError(
                f"MySQL CA certificate not found: {ca_path}"
            )

        return {
            "ssl_ca": ca_path,
            "ssl_verify_cert": True,
        }

    if os.getenv("DB_SSL", "").strip().lower() in (
        "1", "true", "yes", "on"
    ):
        return {"ssl_disabled": False}

    return {}

# The connector's pool never waits: when every connection is busy it fails at once with PoolError.
# So we wait here (a few seconds at most) for one to come back instead of failing the request.
POOL_WAIT = float(os.getenv("DB_POOL_WAIT", "5"))


def get_db_connection():
    """Pooled connection (conn.close() returns it to the pool). None on failure."""
    global _pool
    missing = [k for k in _REQUIRED if os.getenv(k) is None]
    if missing:
        print(f"Database Connection Error: missing env vars: {', '.join(missing)}")
        return None
    try:
        with _pool_lock:
            if _pool is None:
                _pool = pooling.MySQLConnectionPool(
                    pool_name="campusfix",
                    pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
                    pool_reset_session=True,
                    host=os.getenv("DB_HOST"),
                    port=int(os.getenv("DB_PORT", "3306")),
                    user=os.getenv("DB_USER"),
                    password=os.getenv("DB_PASSWORD"),
                    database=os.getenv("DB_NAME"),
                    charset="utf8mb4",
                    collation="utf8mb4_unicode_ci",
                    connection_timeout=10,
                    **_ssl_options(),
                )
        deadline = time.monotonic() + POOL_WAIT
        while True:
            try:
                return _pool.get_connection()
            except PoolError:                      # all connections busy right now
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
    except (Error, ValueError) as err:
        print(f"Database Connection Error: {err}")
        return None


TABLE_OPTS = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
TABLE_OPTS = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"

TABLES = [
    # users: students + admins/HOD
    f"""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'student',
        roll_number VARCHAR(100) NULL,
        course_year VARCHAR(100) NULL,
        profile_photo LONGTEXT NULL,
        phone VARCHAR(20) NULL,
        Residence VARCHAR(100) NULL,
        room_no VARCHAR(50) NULL,
        emp_id VARCHAR(40) NULL,
        dept VARCHAR(80) NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_users_email (email),
        UNIQUE KEY uq_users_roll (roll_number)
    ) {TABLE_OPTS}
    """,
    # staff
    f"""
    CREATE TABLE IF NOT EXISTS staff (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(120) NOT NULL,
        dept VARCHAR(80) NULL,
        role VARCHAR(60) NULL,
        phone VARCHAR(20) NULL,
        password VARCHAR(255) NOT NULL,
        active TINYINT NOT NULL DEFAULT 1,
        profile_photo LONGTEXT NULL,
        must_change_password TINYINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_staff_email (email)
    ) {TABLE_OPTS}
    """,
    # complaints
    f"""
    CREATE TABLE IF NOT EXISTS complaints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        location VARCHAR(255) NULL,
        category VARCHAR(100) NULL,
        priority VARCHAR(50) NOT NULL DEFAULT 'Medium',
        status VARCHAR(50) NOT NULL DEFAULT 'Pending',
        photo LONGTEXT NULL,
        client_cid VARCHAR(64) NULL,
        assigned_to INT NULL,
        escalated TINYINT NOT NULL DEFAULT 0,
        rating TINYINT NULL,
        resolved_at DATETIME NULL,
        resolved_by VARCHAR(100) NULL,
        notified_at DATETIME NULL,
        resolution_note TEXT NULL,
        resolution_photo LONGTEXT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_student_cid (student_id, client_cid),
        KEY idx_complaints_status (status),
        KEY idx_complaints_assigned (assigned_to),
        KEY idx_complaints_created (created_at),
        CONSTRAINT fk_complaints_student FOREIGN KEY (student_id)
            REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_complaints_staff FOREIGN KEY (assigned_to)
            REFERENCES staff(id) ON DELETE SET NULL
    ) {TABLE_OPTS}
    """,
    # activity log
    f"""
    CREATE TABLE IF NOT EXISTS complaint_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        complaint_id INT NOT NULL,
        kind VARCHAR(20) NULL,
        msg VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_log_complaint (complaint_id),
        CONSTRAINT fk_log_complaint FOREIGN KEY (complaint_id)
            REFERENCES complaints(id) ON DELETE CASCADE
    ) {TABLE_OPTS}
    """,
    f"""
    CREATE TABLE IF NOT EXISTS user_notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        complaint_id INT NULL,
        title VARCHAR(120) NOT NULL,
        message VARCHAR(500) NOT NULL,
        is_read TINYINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_notif_user (user_id, id),
        CONSTRAINT fk_notif_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_notif_complaint FOREIGN KEY (complaint_id)
            REFERENCES complaints(id) ON DELETE CASCADE
    ) {TABLE_OPTS}
    """,
]

# For databases that already exist: CREATE TABLE IF NOT EXISTS will not touch
# them, so add the new indexes / foreign keys separately (safe to re-run).
UPGRADES = [
    ("users", "INDEX", "uq_users_roll", "ADD UNIQUE KEY uq_users_roll (roll_number)"),
    ("complaints", "INDEX", "idx_complaints_status", "ADD KEY idx_complaints_status (status)"),
    ("complaints", "INDEX", "idx_complaints_assigned", "ADD KEY idx_complaints_assigned (assigned_to)"),
    ("complaints", "INDEX", "idx_complaints_created", "ADD KEY idx_complaints_created (created_at)"),
    ("complaints", "FK", "fk_complaints_staff",
     "ADD CONSTRAINT fk_complaints_staff FOREIGN KEY (assigned_to) REFERENCES staff(id) ON DELETE SET NULL"),
    ("complaint_log", "FK", "fk_log_complaint",
     "ADD CONSTRAINT fk_log_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE"),
]


LEGACY_ADD = [
    ("users", "profile_photo", "LONGTEXT NULL"),
    ("users", "phone", "VARCHAR(20) NULL"),
    ("users", "Residence", "VARCHAR(100) NULL"),
    ("users", "room_no", "VARCHAR(50) NULL"),
    ("users", "emp_id", "VARCHAR(40) NULL"),
    ("users", "dept", "VARCHAR(80) NULL"),
    ("complaints", "photo", "LONGTEXT NULL"),
]

LEGACY_WIDEN = [
    ("users", "role", 50, "NOT NULL DEFAULT 'student'"),
    ("complaints", "priority", 50, "NOT NULL DEFAULT 'Medium'"),
    ("complaints", "status", 50, "NOT NULL DEFAULT 'Pending'"),
    ("complaints", "title", 255, "NOT NULL"),
    ("complaints", "location", 255, "NULL"),
    ("complaints", "category", 100, "NULL"),
    ("users", "name", 255, "NOT NULL"),
    ("users", "email", 255, "NOT NULL"),
    ("users", "roll_number", 100, "NULL"),
    ("users", "course_year", 100, "NULL"),
]


def fix_legacy_columns(cur):
    cur.execute("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH "
                "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE()")
    cols = {(str(t).lower(), str(c).lower()): (str(d).lower(), l) for t, c, d, l in cur.fetchall()}
    tables = {t for t, _ in cols}
    for table, col, ddl in LEGACY_ADD:
        if table in tables and (table, col.lower()) not in cols:
            run_alter(cur, f"ALTER TABLE {table} ADD COLUMN {col} {ddl}", f"added {table}.{col}")
    for table, col, length, ddl in LEGACY_WIDEN:
        info = cols.get((table, col))
        if info and (info[0] == "enum" or (info[0] in ("varchar", "char") and (info[1] or 0) < length)):
            run_alter(cur, f"ALTER TABLE {table} MODIFY {col} VARCHAR({length}) {ddl}", f"widened {table}.{col}")


def run_alter(cur, sql, done):
    try:
        cur.execute(sql)
        print(f"schema: {done}")
    except Error as e:
        print(f"WARNING: {done} failed: {e}")


def _exists(cur, table, kind, name):
    if kind == "INDEX":
        cur.execute("SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() "
                    "AND TABLE_NAME = %s AND INDEX_NAME = %s LIMIT 1", (table, name))
    else:
        cur.execute("SELECT 1 FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA = DATABASE() "
                    "AND TABLE_NAME = %s AND CONSTRAINT_NAME = %s LIMIT 1", (table, name))
    return cur.fetchone() is not None


def init_db():
    conn = get_db_connection()
    if not conn:
        return False
    cur = conn.cursor()
    try:
        for ddl in TABLES:
            cur.execute(ddl)
        conn.commit()
        fix_legacy_columns(cur)
        conn.commit()
        for table, kind, name, ddl in UPGRADES:
            if _exists(cur, table, kind, name):
                continue
            try:
                cur.execute(f"ALTER TABLE {table} {ddl}")
                conn.commit()
                print(f"schema: added {kind.lower()} {name}")
            except Error as e:   # e.g. duplicate roll numbers or orphan rows already exist
                print(f"WARNING: could not add {name}: {e}")
        print("SUCCESS: database tables checked/created.")
        return True
    except Error as e:
        print(f"Table Creation Error: {e}")
        return False
    finally:
        cur.close()
        conn.close()


def create_admin(name, email, password):
    """First admin has to come from somewhere: python db.py create-admin"""
    from werkzeug.security import generate_password_hash
    init_db()
    conn = get_db_connection()
    if not conn:
        return False
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'admin')",
                    (name, email.strip().lower(), generate_password_hash(password)))
        conn.commit()
        print(f"Admin created: {email}")
        return True
    except Error as e:
        print(f"Could not create admin: {e}")
        return False
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        from getpass import getpass
        create_admin(input("Name: ").strip(), input("Email: ").strip(), getpass("Password: "))
    else:
        init_db()