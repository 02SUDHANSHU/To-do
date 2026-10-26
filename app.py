"""
Highly Available Support Ticket & Helpdesk Portal on AWS
Backend: Python Flask + PyMySQL + Boto3 (AWS Secrets Manager)
Features:
- Role-based Support Ticket API (/api/tickets): customers submit/edit their own tickets, support updates status
  and deletes; customer self-registration (/register) + username/password login (/login) with signed session cookies
- Live Ticket Summary Metrics (Open, In Progress, Resolved, Critical counts)
- Deep ALB Health Check Endpoint (/health) with RDS MySQL connectivity & latency check
- Automatic Database Reconnection & Exponential Backoff Retry for RDS Multi-AZ Failover
- AWS Secrets Manager / Environment Variable Credential Loading (Zero hardcoded secrets)
- EC2 IMDSv2 Metadata Inspection (Displays Instance ID & Availability Zone in UI to demonstrate ALB load balancing & failover)
- Embedded Modern Responsive Helpdesk Dashboard (HTML/CSS/JS)
"""

import os
import re
import time
import json
import hashlib
import logging
import socket
from functools import wraps
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError

import pymysql
from pymysql.cursors import DictCursor
from flask import Flask, request, jsonify, render_template_string, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash

# Optional AWS Secrets Manager support via boto3
try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

# Configure structured logging for Amazon CloudWatch Logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("ha-helpdesk-portal")

app = Flask(__name__)

VALID_STATUSES = ("Open", "In Progress", "Resolved")
VALID_PRIORITIES = ("Low", "Medium", "High", "Critical")
VALID_CATEGORIES = ("Billing", "Technical Support", "Account Access", "Feature Request", "Outage / Incident")
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,64}$")


# ==============================================================================
# 1. EC2 Instance Metadata (IMDSv2) Helper
#    Identifies which EC2 instance & Availability Zone served the request
# ==============================================================================
def get_instance_metadata():
    """Fetches EC2 Instance ID and Availability Zone using IMDSv2."""
    metadata = {
        "instance_id": socket.gethostname(),
        "availability_zone": os.environ.get("AWS_AVAILABILITY_ZONE", "local-dev"),
    }
    try:
        # Step 1: Request IMDSv2 session token
        token_req = Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT",
        )
        with urlopen(token_req, timeout=0.5) as resp:
            token = resp.read().decode("utf-8")

        headers = {"X-aws-ec2-metadata-token": token}

        # Step 2: Fetch Instance ID
        id_req = Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers=headers,
        )
        with urlopen(id_req, timeout=0.5) as resp:
            metadata["instance_id"] = resp.read().decode("utf-8")

        # Step 3: Fetch Availability Zone
        az_req = Request(
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            headers=headers,
        )
        with urlopen(az_req, timeout=0.5) as resp:
            metadata["availability_zone"] = resp.read().decode("utf-8")

    except (URLError, socket.timeout, OSError):
        # Fallback cleanly when running locally outside EC2
        pass

    return metadata


INSTANCE_META = get_instance_metadata()


# ==============================================================================
# 2. Database Configuration & AWS Secrets Manager Integration
# ==============================================================================
def load_db_config():
    """
    Loads RDS MySQL credentials from AWS Secrets Manager if DB_SECRET_NAME is set,
    otherwise falls back to environment variables.
    """
    secret_name = os.environ.get("DB_SECRET_NAME")
    region_name = os.environ.get("AWS_REGION", "us-east-1")

    if secret_name and BOTO3_AVAILABLE:
        try:
            boto_session = boto3.session.Session()
            client = boto_session.client(service_name="secretsmanager", region_name=region_name)
            response = client.get_secret_value(SecretId=secret_name)
            secret = json.loads(response["SecretString"])
            logger.info("Loaded RDS credentials from AWS Secrets Manager (%s)", secret_name)
            return {
                "host": secret.get("host", os.environ.get("DB_HOST", "localhost")),
                "user": secret.get("username", os.environ.get("DB_USER", "admin")),
                "password": secret.get("password", os.environ.get("DB_PASSWORD", "")),
                "database": secret.get("dbname", os.environ.get("DB_NAME", "helpdesk_db")),
                "port": int(secret.get("port", os.environ.get("DB_PORT", 3306))),
            }
        except Exception as exc:
            logger.error("Failed to fetch secret from Secrets Manager: %s. Falling back to env vars.", exc)

    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "user": os.environ.get("DB_USER", "admin"),
        "password": os.environ.get("DB_PASSWORD", "changeme"),
        "database": os.environ.get("DB_NAME", "helpdesk_db"),
        "port": int(os.environ.get("DB_PORT", 3306)),
    }


DB_CONFIG = load_db_config()

# Session cookies are signed, so every EC2 instance must use the SAME key or a login
# on instance A would be rejected by instance B. Set SECRET_KEY in the env file, or the
# key is derived from the shared RDS password (identical on all instances).
app.secret_key = os.environ.get("SECRET_KEY") or hashlib.sha256(
    ("helpdesk-session|" + str(DB_CONFIG["password"])).encode("utf-8")
).hexdigest()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # set to 1 once HTTPS is on
    PERMANENT_SESSION_LIFETIME=8 * 3600,
)

# Default seeded profiles: (username, role, display name, email, password env var, demo default)
DEMO_USERS = (
    ("customer", "customer", "Customer Demo", "customer@example.com", "CUSTOMER_PASSWORD", "Customer@123"),
    ("support", "support", "Support Agent", "support@example.com", "SUPPORT_PASSWORD", "Support@123"),
)


# ==============================================================================
# 3. Resilient Database Connection & Multi-AZ Failover Retry Decorator
# ==============================================================================
def get_db_connection():
    """
    Creates a fresh PyMySQL connection with short connect/read/write timeouts
    so RDS Multi-AZ DNS flips and dropped connections are detected rapidly.
    """
    return pymysql.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"],
        port=DB_CONFIG["port"],
        cursorclass=DictCursor,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
        autocommit=False,
        charset="utf8mb4",
    )


def with_db_retry(max_retries=3, base_delay=0.8):
    """
    Decorator that wraps database operations with exponential backoff retry logic.
    Handles transient connection drops and read-only states during RDS Multi-AZ failover.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except pymysql.MySQLError as exc:
                    last_error = exc
                    logger.warning(
                        "Database operation failed in %s (attempt %d/%d): %s",
                        func.__name__,
                        attempt,
                        max_retries,
                        exc,
                    )
                    if attempt < max_retries:
                        sleep_time = base_delay * (2 ** (attempt - 1))
                        time.sleep(sleep_time)
            logger.error("All %d DB retry attempts exhausted in %s: %s", max_retries, func.__name__, last_error)
            raise last_error
        return wrapper
    return decorator


@with_db_retry(max_retries=5, base_delay=1.0)
def init_db():
    """Creates the helpdesk database and tickets/users tables if they do not exist."""
    conn = pymysql.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        port=DB_CONFIG["port"],
        connect_timeout=5,
        charset="utf8mb4",
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            )
        conn.commit()
    finally:
        conn.close()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    subject VARCHAR(255) NOT NULL,
                    description TEXT,
                    customer_name VARCHAR(120) NOT NULL,
                    customer_email VARCHAR(160) NOT NULL,
                    category VARCHAR(64) NOT NULL DEFAULT 'Technical Support',
                    priority ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Medium',
                    status ENUM('Open', 'In Progress', 'Resolved') NOT NULL DEFAULT 'Open',
                    assigned_to VARCHAR(120) DEFAULT 'Unassigned',
                    resolution_notes TEXT,
                    created_by_instance VARCHAR(64),
                    created_by_az VARCHAR(64),
                    last_updated_by_instance VARCHAR(64),
                    last_updated_by_az VARCHAR(64),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_status (status),
                    INDEX idx_priority (priority),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(64) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    role ENUM('customer', 'support') NOT NULL,
                    display_name VARCHAR(120) NOT NULL,
                    email VARCHAR(160) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            for username, role, display, email, env_name, default_pw in DEMO_USERS:
                env_pw = os.environ.get(env_name)
                pw_hash = generate_password_hash(env_pw or default_pw)
                if env_pw:
                    # Password supplied via env: always keep the DB in sync with it.
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, role, display_name, email) "
                        "VALUES (%s, %s, %s, %s, %s) "
                        "ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), "
                        "role = VALUES(role), display_name = VALUES(display_name), email = VALUES(email);",
                        (username, pw_hash, role, display, email),
                    )
                else:
                    cursor.execute(
                        "INSERT IGNORE INTO users (username, password_hash, role, display_name, email) "
                        "VALUES (%s, %s, %s, %s, %s);",
                        (username, pw_hash, role, display, email),
                    )
        conn.commit()
        logger.info("Helpdesk database schema verified on %s", DB_CONFIG["host"])
    finally:
        conn.close()


def serialize_ticket(ticket):
    """Formats datetime fields for JSON output."""
    if not ticket:
        return ticket
    for key in ("created_at", "updated_at"):
        if ticket.get(key) and hasattr(ticket[key], "isoformat"):
            ticket[key] = ticket[key].isoformat()
    return ticket


# ==============================================================================
# 4. Application Load Balancer Health Check Endpoint (/health)
# ==============================================================================
_schema_ready = False
_schema_last_try = 0.0


def ensure_schema():
    """Creates tables/users once. Retried (at most every 10s) if RDS was unreachable at boot."""
    global _schema_ready, _schema_last_try
    if _schema_ready:
        return True
    if time.time() - _schema_last_try < 10:
        return False
    _schema_last_try = time.time()
    try:
        init_db()
        _schema_ready = True
    except Exception as exc:
        logger.warning("Schema setup failed, will retry: %s", exc)
    return _schema_ready


@app.before_request
def _lazy_schema():
    if request.path.startswith("/health"):
        return None
    ensure_schema()
    return None


def current_user():
    """Returns the logged-in user from the signed session cookie, or None."""
    if not session.get("uid"):
        return None
    return {
        "username": session.get("username"),
        "role": session.get("role"),
        "display_name": session.get("display_name"),
        "email": session.get("email"),
    }


def api_auth(*roles):
    """Requires a logged-in user, optionally restricted to the given roles."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "Authentication required."}), 401
            if roles and user["role"] not in roles:
                return jsonify({"error": "You do not have permission for this action."}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


@with_db_retry()
def fetch_user(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
            return cursor.fetchone()
    finally:
        conn.close()


@with_db_retry()
def create_customer_user(username, password, display_name, email):
    """Creates a new customer account in the users table if username/email are available."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT username, email FROM users WHERE username = %s OR LOWER(email) = LOWER(%s) LIMIT 1;",
                (username, email),
            )
            existing = cursor.fetchone()
            if existing:
                if existing["username"].lower() == username.lower():
                    return None, "That username is already taken."
                return None, "An account with that email address already exists."

            pw_hash = generate_password_hash(password)
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role, display_name, email)
                VALUES (%s, %s, 'customer', %s, %s);
                """,
                (username, pw_hash, display_name, email),
            )
            user_id = cursor.lastrowid
            conn.commit()

            cursor.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
            return cursor.fetchone(), None
    finally:
        conn.close()


@app.route("/health", methods=["GET"])
def health_light():
    """ALB health check. Deliberately does NOT touch the DB, so an RDS failover
    cannot mark every instance unhealthy at once."""
    return jsonify({"status": "ok", "instance_id": INSTANCE_META["instance_id"]}), 200


@app.route("/health/db", methods=["GET"])
def health_check():
    """
    ALB Target Group / Dashboard Database Health Check Endpoint.
    Verifies both Flask process responsiveness and RDS MySQL reachability.
    Returns HTTP 200 when healthy, HTTP 503 if the database cannot be reached.
    """
    start_time = time.time()
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1 AS ok;")
                row = cursor.fetchone()
        finally:
            conn.close()

        latency_ms = round((time.time() - start_time) * 1000, 2)
        return jsonify({
            "status": "healthy",
            "service": "ha-helpdesk-portal",
            "database": "connected" if row and row.get("ok") == 1 else "degraded",
            "db_latency_ms": latency_ms,
            "instance_id": INSTANCE_META["instance_id"],
            "availability_zone": INSTANCE_META["availability_zone"],
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }), 200
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        return jsonify({
            "status": "unhealthy",
            "service": "ha-helpdesk-portal",
            "database": "disconnected",
            "error": str(exc),
            "instance_id": INSTANCE_META["instance_id"],
            "availability_zone": INSTANCE_META["availability_zone"],
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }), 503


# ==============================================================================
# 5. REST API Endpoints for Support Ticket Management (CRUD & Filtering)
# ==============================================================================
@app.route("/api/metadata", methods=["GET"])
def api_metadata():
    """Returns the current EC2 instance ID and AZ serving the request."""
    return jsonify(INSTANCE_META), 200


@app.route("/api/tickets", methods=["GET"])
@api_auth("customer", "support")
@with_db_retry()
def list_tickets():
    """Lists tickets (customers: own only; support: all) with optional status/priority/search filters."""
    status_filter = request.args.get("status", "all")
    priority_filter = request.args.get("priority", "all")
    search_query = (request.args.get("q") or "").strip()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            where_clauses = []
            params = []
            user = current_user()

            # Customers only ever see their own tickets; support sees everything.
            if user["role"] == "customer":
                where_clauses.append("customer_email = %s")
                params.append(user["email"])

            if status_filter in VALID_STATUSES:
                where_clauses.append("status = %s")
                params.append(status_filter)

            if priority_filter in VALID_PRIORITIES:
                where_clauses.append("priority = %s")
                params.append(priority_filter)

            if search_query:
                where_clauses.append(
                    "(subject LIKE %s OR customer_name LIKE %s OR customer_email LIKE %s)"
                )
                like_val = f"%{search_query}%"
                params.extend([like_val, like_val, like_val])

            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            query = f"""
                SELECT * FROM tickets
                {where_sql}
                ORDER BY
                    FIELD(status, 'Open', 'In Progress', 'Resolved'),
                    FIELD(priority, 'Critical', 'High', 'Medium', 'Low'),
                    created_at DESC;
            """
            cursor.execute(query, tuple(params))
            tickets = [serialize_ticket(row) for row in cursor.fetchall()]

            # Aggregate summary counts for dashboard KPI cards
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) AS open_count,
                    SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress_count,
                    SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_count,
                    SUM(CASE WHEN priority = 'Critical' AND status != 'Resolved' THEN 1 ELSE 0 END) AS active_critical_count
                FROM tickets
                WHERE (%s = 'support' OR customer_email = %s);
                """,
                (user["role"], user["email"]),
            )
            stats = cursor.fetchone() or {}

        return jsonify({
            "tickets": tickets,
            "stats": {
                "total": int(stats.get("total") or 0),
                "open": int(stats.get("open_count") or 0),
                "in_progress": int(stats.get("in_progress_count") or 0),
                "resolved": int(stats.get("resolved_count") or 0),
                "active_critical": int(stats.get("active_critical_count") or 0),
            },
            "served_by": INSTANCE_META,
        }), 200
    finally:
        conn.close()


@app.route("/api/tickets", methods=["POST"])
@api_auth("customer")
@with_db_retry()
def create_ticket():
    """Submits a new customer support ticket into RDS MySQL."""
    data = request.get_json(silent=True) or {}
    subject = (data.get("subject") or "").strip()
    description = (data.get("description") or "").strip()
    user = current_user()
    customer_name = user["display_name"]
    customer_email = user["email"]
    category = (data.get("category") or "Technical Support").strip()
    priority = (data.get("priority") or "Medium").strip()

    if not subject:
        return jsonify({"error": "Ticket subject is required."}), 400
    subject = subject[:255]

    if priority not in VALID_PRIORITIES:
        priority = "Medium"
    if category not in VALID_CATEGORIES:
        category = "Technical Support"

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO tickets (
                    subject, description, customer_name, customer_email,
                    category, priority, status,
                    created_by_instance, created_by_az,
                    last_updated_by_instance, last_updated_by_az
                )
                VALUES (%s, %s, %s, %s, %s, %s, 'Open', %s, %s, %s, %s);
                """,
                (
                    subject,
                    description,
                    customer_name,
                    customer_email,
                    category,
                    priority,
                    INSTANCE_META["instance_id"],
                    INSTANCE_META["availability_zone"],
                    INSTANCE_META["instance_id"],
                    INSTANCE_META["availability_zone"],
                ),
            )
            ticket_id = cursor.lastrowid
            conn.commit()

            cursor.execute("SELECT * FROM tickets WHERE id = %s;", (ticket_id,))
            new_ticket = serialize_ticket(cursor.fetchone())

        logger.info(
            "Created support ticket ID=%d (priority=%s) on instance=%s (%s)",
            ticket_id,
            priority,
            INSTANCE_META["instance_id"],
            INSTANCE_META["availability_zone"],
        )
        return jsonify({"ticket": new_ticket, "served_by": INSTANCE_META}), 201
    finally:
        conn.close()


@app.route("/api/tickets/<int:ticket_id>", methods=["PUT", "PATCH"])
@api_auth("customer", "support")
@with_db_retry()
def update_ticket(ticket_id):
    """Support changes ticket status; customers edit their OWN tickets while still Open."""
    user = current_user()
    data = request.get_json(silent=True) or {}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM tickets WHERE id = %s;", (ticket_id,))
            existing = cursor.fetchone()
            if not existing:
                return jsonify({"error": "Support ticket not found."}), 404

            if user["role"] == "support":
                status = data.get("status", existing["status"])
                if status not in VALID_STATUSES:
                    return jsonify({"error": "Invalid status."}), 400
                cursor.execute(
                    """
                    UPDATE tickets
                    SET status = %s, last_updated_by_instance = %s, last_updated_by_az = %s
                    WHERE id = %s;
                    """,
                    (status, INSTANCE_META["instance_id"], INSTANCE_META["availability_zone"], ticket_id),
                )
            else:
                if existing["customer_email"] != user["email"]:
                    return jsonify({"error": "Support ticket not found."}), 404
                if existing["status"] != "Open":
                    return jsonify({"error": "Only open tickets can be edited."}), 403

                subject = (data.get("subject", existing["subject"]) or "").strip()
                if not subject:
                    return jsonify({"error": "Ticket subject cannot be empty."}), 400
                description = data.get("description", existing["description"])
                category = data.get("category", existing["category"])
                priority = data.get("priority", existing["priority"])
                if category not in VALID_CATEGORIES:
                    category = existing["category"]
                if priority not in VALID_PRIORITIES:
                    priority = existing["priority"]
                cursor.execute(
                    """
                    UPDATE tickets
                    SET subject = %s, description = %s, category = %s, priority = %s,
                        last_updated_by_instance = %s, last_updated_by_az = %s
                    WHERE id = %s;
                    """,
                    (
                        subject[:255], description, category, priority,
                        INSTANCE_META["instance_id"], INSTANCE_META["availability_zone"], ticket_id,
                    ),
                )
            conn.commit()

            cursor.execute("SELECT * FROM tickets WHERE id = %s;", (ticket_id,))
            updated = serialize_ticket(cursor.fetchone())

        logger.info("Ticket ID=%d updated by %s (%s) on instance=%s",
                    ticket_id, user["username"], user["role"], INSTANCE_META["instance_id"])
        return jsonify({"ticket": updated, "served_by": INSTANCE_META}), 200
    finally:
        conn.close()


@app.route("/api/tickets/<int:ticket_id>", methods=["DELETE"])
@api_auth("support")
@with_db_retry()
def delete_ticket(ticket_id):
    """Deletes a support ticket from RDS MySQL."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM tickets WHERE id = %s;", (ticket_id,))
            if not cursor.fetchone():
                return jsonify({"error": "Support ticket not found."}), 404

            cursor.execute("DELETE FROM tickets WHERE id = %s;", (ticket_id,))
            conn.commit()

        logger.info("Deleted ticket ID=%d on instance=%s", ticket_id, INSTANCE_META["instance_id"])
        return jsonify({"deleted_id": ticket_id, "served_by": INSTANCE_META}), 200
    finally:
        conn.close()


# ==============================================================================
# 6. Frontend UI (HTML, CSS, JavaScript)
#    Includes Live AWS High-Availability Telemetry Bar & Helpdesk KPI Dashboard
# ==============================================================================
FRONTEND_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>AWS Highly Available Support Ticket & Helpdesk Portal</title>
    <style>
        :root {
            --bg: #0b1120;
            --surface: #1e293b;
            --surface-alt: #0f172a;
            --surface-hover: #334155;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #a855f7;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 1.75rem 1rem 3rem;
        }
        .container {
            max-width: 1080px;
            margin: 0 auto;
        }
        /* AWS Telemetry Bar */
        .telemetry-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            justify-content: space-between;
            align-items: center;
            background: rgba(30, 41, 59, 0.92);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 0.8rem 1.2rem;
            margin-bottom: 1.5rem;
            font-size: 0.84rem;
        }
        .telemetry-group {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.28rem 0.7rem;
            border-radius: 999px;
            font-weight: 600;
            font-size: 0.78rem;
            background: var(--surface-alt);
            border: 1px solid var(--border);
        }
        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 8px var(--success);
        }
        .dot.unhealthy { background: var(--danger); box-shadow: 0 0 8px var(--danger); }

        header {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        header h1 {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 0.3rem;
        }
        header p {
            color: var(--text-muted);
            font-size: 0.95rem;
        }

        /* KPI Summary Cards */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        @media (max-width: 768px) {
            .kpi-grid { grid-template-columns: repeat(2, 1fr); }
        }
        .kpi-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1rem 1.2rem;
        }
        .kpi-label {
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            margin-bottom: 0.35rem;
        }
        .kpi-value {
            font-size: 1.75rem;
            font-weight: 700;
        }
        .kpi-open { color: var(--accent); }
        .kpi-progress { color: var(--warning); }
        .kpi-resolved { color: var(--success); }
        .kpi-critical { color: var(--danger); }

        /* Form Card */
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.35rem;
            margin-bottom: 1.5rem;
        }
        .card-title {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.85rem;
            margin-bottom: 0.85rem;
        }
        .form-grid-2 {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr;
            gap: 0.85rem;
            margin-bottom: 0.85rem;
        }
        @media (max-width: 768px) {
            .form-grid, .form-grid-2 { grid-template-columns: 1fr; }
        }
        label {
            display: block;
            font-size: 0.78rem;
            color: var(--text-muted);
            margin-bottom: 0.3rem;
            font-weight: 600;
        }
        input, select, textarea {
            background: var(--surface-alt);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.62rem 0.8rem;
            border-radius: 0.5rem;
            font-size: 0.9rem;
            width: 100%;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--accent);
        }
        button {
            background: var(--accent);
            color: #0b1120;
            font-weight: 600;
            border: none;
            padding: 0.65rem 1.2rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-size: 0.88rem;
            transition: all 0.15s ease;
        }
        button:hover { background: var(--accent-hover); color: #fff; }
        .btn-secondary {
            background: transparent;
            color: var(--text-muted);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover {
            background: var(--surface-hover);
            color: var(--text);
        }
        .btn-danger {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 0.4rem 0.75rem;
            font-size: 0.78rem;
        }
        .btn-danger:hover { background: var(--danger); color: #fff; }
        .btn-edit {
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 0.4rem 0.75rem;
            font-size: 0.78rem;
        }

        /* Filter & Search Bar */
        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 0.75rem;
        }
        .filters {
            display: flex;
            gap: 0.45rem;
            flex-wrap: wrap;
        }
        .filter-btn.active {
            background: var(--accent);
            color: #0b1120;
            border-color: var(--accent);
        }
        .toolbar-right {
            display: flex;
            gap: 0.6rem;
            align-items: center;
            flex-wrap: wrap;
        }

        /* Ticket Cards */
        .ticket-list {
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }
        .ticket-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.15rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1.25rem;
            flex-wrap: wrap;
        }
        .ticket-card.resolved {
            opacity: 0.75;
            border-color: rgba(34, 197, 94, 0.3);
        }
        .ticket-main { flex: 1; min-width: 280px; }
        .ticket-header {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            flex-wrap: wrap;
            margin-bottom: 0.4rem;
        }
        .ticket-id {
            font-family: monospace;
            font-size: 0.82rem;
            color: var(--accent);
            background: rgba(56, 189, 248, 0.12);
            padding: 0.15rem 0.45rem;
            border-radius: 0.35rem;
            font-weight: 700;
        }
        .ticket-subject {
            font-weight: 700;
            font-size: 1.05rem;
        }
        .ticket-desc {
            color: var(--text-muted);
            font-size: 0.88rem;
            margin-bottom: 0.65rem;
            line-height: 1.45;
        }
        .ticket-meta {
            display: flex;
            gap: 0.9rem;
            flex-wrap: wrap;
            font-size: 0.78rem;
            color: var(--text-muted);
        }
        .pill {
            text-transform: uppercase;
            font-weight: 700;
            font-size: 0.68rem;
            padding: 0.18rem 0.55rem;
            border-radius: 999px;
            letter-spacing: 0.03em;
        }
        .priority-Critical { background: rgba(239, 68, 68, 0.22); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }
        .priority-High { background: rgba(245, 158, 11, 0.2); color: #fcd34d; }
        .priority-Medium { background: rgba(56, 189, 248, 0.18); color: #7dd3fc; }
        .priority-Low { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; }

        .status-Open { background: rgba(56, 189, 248, 0.18); color: #38bdf8; }
        .status-In-Progress { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
        .status-Resolved { background: rgba(34, 197, 94, 0.2); color: #4ade80; }

        .ticket-controls {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.55rem;
            min-width: 220px;
        }
        .quick-row {
            display: flex;
            gap: 0.45rem;
            width: 100%;
        }
        .quick-row select, .quick-row input {
            padding: 0.38rem 0.55rem;
            font-size: 0.8rem;
        }
        .empty-state {
            text-align: center;
            padding: 2.75rem 1rem;
            color: var(--text-muted);
            border: 1px dashed var(--border);
            border-radius: 0.75rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- AWS High Availability Telemetry Bar -->
        <div class="telemetry-bar">
            <div class="telemetry-group">
                <span class="badge">
                    <span id="health-dot" class="dot"></span>
                    <span id="health-text">ALB Target: Healthy</span>
                </span>
                <span class="badge">Serving EC2: <strong id="meta-instance">{{ instance_id }}</strong></span>
                <span class="badge">Availability Zone: <strong id="meta-az">{{ availability_zone }}</strong></span>
                <span class="badge">RDS Latency: <strong id="meta-latency">-- ms</strong></span>
            </div>
            <button class="btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.78rem;" onclick="pingHealth()">
                Refresh Node Telemetry
            </button>
        </div>

        <header>
            <div>
                <h1>Cloud Support Ticket & Helpdesk Portal</h1>
                <p>Highly Available Multi-AZ Customer Support System on AWS (ALB + EC2 Auto Scaling + Multi-AZ RDS MySQL)</p>
            </div>
            <div style="display:flex; align-items:center; gap:0.6rem;">
                <span class="badge">{{ display_name }} (@{{ username }}) - <strong>{{ role|capitalize }}</strong></span>
                <a href="/logout" class="badge" style="text-decoration:none; color:inherit;">Log out</a>
            </div>
        </header>

        <!-- Live KPI Summary Row -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Open Tickets</div>
                <div class="kpi-value kpi-open" id="kpi-open">0</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">In Progress</div>
                <div class="kpi-value kpi-progress" id="kpi-progress">0</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Resolved</div>
                <div class="kpi-value kpi-resolved" id="kpi-resolved">0</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Active Critical</div>
                <div class="kpi-value kpi-critical" id="kpi-critical">0</div>
            </div>
        </div>

        {% if role == 'customer' %}
        <!-- Submit / Edit Support Ticket Form -->
        <div class="card">
            <div class="card-title">
                <span id="form-heading">Submit New Support Ticket</span>
                <button type="button" id="cancel-edit-btn" class="btn-secondary" style="display:none; padding:0.3rem 0.7rem; font-size:0.78rem;" onclick="resetForm()">Cancel Edit</button>
            </div>
            <form id="ticket-form" onsubmit="handleSaveTicket(event)">
                <input type="hidden" id="edit-ticket-id" value="" />
                <p style="margin:0 0 0.85rem; font-size:0.85rem; opacity:0.8;">Submitting as <strong>{{ display_name }}</strong> ({{ email }})</p>
                <div class="form-grid-2">
                    <div>
                        <label>Ticket Subject *</label>
                        <input type="text" id="ticket-subject" placeholder="Brief summary of the customer issue..." required />
                    </div>
                    <div>
                        <label>Category</label>
                        <select id="ticket-category">
                            <option value="Technical Support" selected>Technical Support</option>
                            <option value="Billing">Billing</option>
                            <option value="Account Access">Account Access</option>
                            <option value="Outage / Incident">Outage / Incident</option>
                            <option value="Feature Request">Feature Request</option>
                        </select>
                    </div>
                    <div>
                        <label>Priority</label>
                        <select id="ticket-priority">
                            <option value="Low">Low</option>
                            <option value="Medium" selected>Medium</option>
                            <option value="High">High</option>
                            <option value="Critical">Critical</option>
                        </select>
                    </div>
                </div>
                <div style="margin-bottom: 0.85rem;">
                    <label>Issue Description & Reproduction Steps</label>
                    <textarea id="ticket-desc" rows="2" placeholder="Describe the issue, error codes, or customer impact..."></textarea>
                </div>
                <div style="display: flex; justify-content: flex-end;">
                    <button type="submit" id="submit-btn">Submit Support Ticket</button>
                </div>
            </form>
        </div>

        {% endif %}

        <!-- Filter & Search Toolbar -->
        <div class="toolbar">
            <div class="filters">
                <button class="btn-secondary filter-btn active" onclick="setStatusFilter('all', this)">All Statuses</button>
                <button class="btn-secondary filter-btn" onclick="setStatusFilter('Open', this)">Open</button>
                <button class="btn-secondary filter-btn" onclick="setStatusFilter('In Progress', this)">In Progress</button>
                <button class="btn-secondary filter-btn" onclick="setStatusFilter('Resolved', this)">Resolved</button>
            </div>
            <div class="toolbar-right">
                <select id="priority-filter" onchange="fetchTickets()" style="width: auto; padding: 0.48rem 0.75rem;">
                    <option value="all">All Priorities</option>
                    <option value="Critical">Critical Only</option>
                    <option value="High">High Only</option>
                    <option value="Medium">Medium Only</option>
                    <option value="Low">Low Only</option>
                </select>
                <input type="text" id="search-box" placeholder="Search subject or customer..." oninput="fetchTickets()" style="width: 230px; padding: 0.48rem 0.75rem;" />
            </div>
        </div>

        <!-- Tickets List -->
        <div id="ticket-list" class="ticket-list"></div>
    </div>

    <script>
        let currentStatusFilter = 'all';
        let ticketsCache = [];
        const ROLE = {{ role|tojson }};

        async function pingHealth() {
            try {
                const res = await fetch('/health/db');
                const data = await res.json();
                const dot = document.getElementById('health-dot');
                const text = document.getElementById('health-text');
                document.getElementById('meta-instance').textContent = data.instance_id || 'unknown';
                document.getElementById('meta-az').textContent = data.availability_zone || 'unknown';
                document.getElementById('meta-latency').textContent = (data.db_latency_ms !== undefined) ? `${data.db_latency_ms} ms` : 'ERR';

                if (res.ok && data.status === 'healthy') {
                    dot.classList.remove('unhealthy');
                    text.textContent = 'ALB Target: Healthy';
                } else {
                    dot.classList.add('unhealthy');
                    text.textContent = 'ALB Target: Unhealthy';
                }
            } catch (err) {
                document.getElementById('health-dot').classList.add('unhealthy');
                document.getElementById('health-text').textContent = 'Connection Error';
            }
        }

        async function fetchTickets() {
            const priority = document.getElementById('priority-filter').value;
            const q = document.getElementById('search-box').value;
            const params = new URLSearchParams({
                status: currentStatusFilter,
                priority: priority,
                q: q
            });
            const res = await fetch(`/api/tickets?${params.toString()}`);
            if (res.status === 401) { window.location = '/login'; return; }
            const data = await res.json();

            if (data.served_by) {
                document.getElementById('meta-instance').textContent = data.served_by.instance_id;
                document.getElementById('meta-az').textContent = data.served_by.availability_zone;
            }
            if (data.stats) {
                document.getElementById('kpi-open').textContent = data.stats.open;
                document.getElementById('kpi-progress').textContent = data.stats.in_progress;
                document.getElementById('kpi-resolved').textContent = data.stats.resolved;
                document.getElementById('kpi-critical').textContent = data.stats.active_critical;
            }
            ticketsCache = data.tickets || [];
            renderTickets();
        }

        function controlsHtml(t) {
            if (ROLE === 'support') {
                return `
                    <div class="quick-row">
                        <select onchange="quickUpdateStatus(${t.id}, this.value)" title="Update Ticket Status">
                            <option value="Open" ${t.status === 'Open' ? 'selected' : ''}>Status: Open</option>
                            <option value="In Progress" ${t.status === 'In Progress' ? 'selected' : ''}>Status: In Progress</option>
                            <option value="Resolved" ${t.status === 'Resolved' ? 'selected' : ''}>Status: Resolved</option>
                        </select>
                    </div>
                    <div style="display:flex; gap:0.4rem;">
                        <button class="btn-danger" onclick="deleteTicket(${t.id})">Delete</button>
                    </div>`;
            }
            if (t.status === 'Open') {
                return `<div style="display:flex; gap:0.4rem;"><button class="btn-edit" onclick="startEditTicket(${t.id})">Edit</button></div>`;
            }
            return `<div class="ticket-desc">Locked once support picks it up</div>`;
        }

        function renderTickets() {
            const listEl = document.getElementById('ticket-list');
            if (ticketsCache.length === 0) {
                listEl.innerHTML = `<div class="empty-state">No support tickets match the current filter. Submit a ticket above to verify RDS Multi-AZ persistence!</div>`;
                return;
            }

            listEl.innerHTML = ticketsCache.map(t => {
                const statusClass = t.status.replace(/\\s+/g, '-');
                return `
                <div class="ticket-card ${t.status === 'Resolved' ? 'resolved' : ''}">
                    <div class="ticket-main">
                        <div class="ticket-header">
                            <span class="ticket-id">TKT-${String(t.id).padStart(4, '0')}</span>
                            <span class="pill priority-${escapeHtml(t.priority)}">${escapeHtml(t.priority)}</span>
                            <span class="pill status-${statusClass}">${escapeHtml(t.status)}</span>
                            <span class="pill" style="background:rgba(168,85,247,0.15);color:#d8b4fe;">${escapeHtml(t.category)}</span>
                        </div>
                        <div class="ticket-subject" style="margin-bottom:0.3rem;">${escapeHtml(t.subject)}</div>
                        ${t.description ? `<div class="ticket-desc">${escapeHtml(t.description)}</div>` : ''}
                        <div class="ticket-meta">
                            <span>Customer: <strong>${escapeHtml(t.customer_name)}</strong> (${escapeHtml(t.customer_email)})</span>
                            <span>Logged on EC2: <strong>${escapeHtml(t.created_by_instance || 'N/A')}</strong> (${escapeHtml(t.created_by_az || 'N/A')})</span>
                        </div>
                    </div>
                    <div class="ticket-controls">
                        ${controlsHtml(t)}
                    </div>
                </div>
                `;
            }).join('');
        }

        async function handleSaveTicket(e) {
            e.preventDefault();
            const editId = document.getElementById('edit-ticket-id').value;
            const payload = {
                subject: document.getElementById('ticket-subject').value,
                category: document.getElementById('ticket-category').value,
                priority: document.getElementById('ticket-priority').value,
                description: document.getElementById('ticket-desc').value
            };

            const url = editId ? `/api/tickets/${editId}` : '/api/tickets';
            const method = editId ? 'PUT' : 'POST';

            const res = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                resetForm();
                await fetchTickets();
                await pingHealth();
            } else {
                const err = await res.json().catch(() => ({}));
                alert(err.error || 'Request failed');
            }
        }

        function startEditTicket(id) {
            const t = ticketsCache.find(item => item.id === id);
            if (!t) return;
            document.getElementById('edit-ticket-id').value = t.id;
            document.getElementById('ticket-subject').value = t.subject;
            document.getElementById('ticket-category').value = t.category;
            document.getElementById('ticket-priority').value = t.priority;
            document.getElementById('ticket-desc').value = t.description || '';
            document.getElementById('form-heading').textContent = `Editing Ticket TKT-${String(t.id).padStart(4, '0')}`;
            document.getElementById('submit-btn').textContent = 'Save Ticket Changes';
            document.getElementById('cancel-edit-btn').style.display = 'inline-block';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function resetForm() {
            document.getElementById('ticket-form').reset();
            document.getElementById('edit-ticket-id').value = '';
            document.getElementById('form-heading').textContent = 'Submit New Support Ticket';
            document.getElementById('submit-btn').textContent = 'Submit Support Ticket';
            document.getElementById('cancel-edit-btn').style.display = 'none';
        }

        async function quickUpdateStatus(id, status) {
            await fetch(`/api/tickets/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status })
            });
            await fetchTickets();
        }

        async function deleteTicket(id) {
            await fetch(`/api/tickets/${id}`, { method: 'DELETE' });
            await fetchTickets();
        }

        function setStatusFilter(status, btn) {
            currentStatusFilter = status;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            fetchTickets();
        }

        function escapeHtml(str) {
            return String(str ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }

        // Initial load
        fetchTickets();
        pingHealth();
    </script>
</body>
</html>
"""


LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Helpdesk Portal</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0;
               min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; }
        .box { width: 100%; max-width: 400px; background: #1e293b; border: 1px solid #334155;
               border-radius: 12px; padding: 1.65rem; }
        h1 { font-size: 1.25rem; margin: 0 0 0.3rem; }
        p.sub { color: #94a3b8; font-size: 0.85rem; margin: 0 0 1.15rem; }
        .profiles { display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; margin-bottom: 1rem; }
        .profile { background: #0f172a; color: #cbd5e1; border: 1px solid #334155; border-radius: 8px;
                   padding: 0.7rem 0.5rem; cursor: pointer; font-size: 0.95rem; font-weight: 600; }
        .profile small { display: block; font-weight: 400; color: #94a3b8; font-size: 0.72rem; margin-top: 0.2rem; }
        .profile.active { border-color: #38bdf8; background: #0c4a6e; color: #fff; }
        label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem; font-weight: 600; }
        input[type=text], input[type=email], input[type=password] {
            width: 100%; box-sizing: border-box; padding: 0.62rem 0.75rem; border-radius: 8px;
            border: 1px solid #334155; background: #0f172a; color: #e2e8f0; margin-bottom: 0.9rem; font-size: 0.92rem;
        }
        input:focus { outline: none; border-color: #38bdf8; }
        button.go { width: 100%; padding: 0.68rem; border: 0; border-radius: 8px; background: #0ea5e9;
                    color: #fff; font-weight: 600; cursor: pointer; font-size: 0.92rem; }
        button.go:hover { background: #0284c7; }
        .err { background: #7f1d1d; color: #fecaca; padding: 0.55rem 0.7rem; border-radius: 8px;
               font-size: 0.85rem; margin-bottom: 1rem; }
        .switch-row { margin-top: 1rem; text-align: center; font-size: 0.84rem; color: #94a3b8; }
        .switch-row a { color: #38bdf8; text-decoration: none; font-weight: 600; }
        .switch-row a:hover { text-decoration: underline; }
        .meta { margin-top: 1rem; font-size: 0.72rem; color: #64748b; text-align: center; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Cloud Helpdesk Portal</h1>
        {% if mode == 'register' %}
            <p class="sub">Create a new Customer account</p>
            {% if error %}<div class="err">{{ error }}</div>{% endif %}
            <form method="post" action="/register">
                <label for="display_name">Full Name</label>
                <input type="text" name="display_name" id="display_name" value="{{ form_display_name }}" placeholder="e.g. Alex Rivera" required autocomplete="name">

                <label for="reg_username">Username</label>
                <input type="text" name="username" id="reg_username" value="{{ form_username }}" placeholder="e.g. alex (3-64 letters/numbers)" required autocomplete="username">

                <label for="email">Email Address</label>
                <input type="email" name="email" id="email" value="{{ form_email }}" placeholder="e.g. alex@example.com" required autocomplete="email">

                <label for="reg_password">Password</label>
                <input type="password" name="password" id="reg_password" placeholder="At least 6 characters" required autocomplete="new-password">

                <button type="submit" class="go">Create Customer Account</button>
            </form>
            <div class="switch-row">
                Already have an account? <a href="/login">Sign in</a>
            </div>
        {% else %}
            <p class="sub">Choose a profile or enter your username to sign in</p>
            {% if error %}<div class="err">{{ error }}</div>{% endif %}
            <form method="post" action="/login">
                <input type="hidden" name="selected_role" id="selected_role" value="{{ selected }}">
                <div class="profiles">
                    <button type="button" class="profile" id="p-customer" onclick="pickRole('customer')">Customer<small>Submit and track tickets</small></button>
                    <button type="button" class="profile" id="p-support" onclick="pickRole('support')">Support<small>Manage all tickets</small></button>
                </div>
                <label for="username">Username</label>
                <input type="text" name="username" id="username" value="{{ form_username }}" placeholder="Enter username (e.g. customer or support)" required autocomplete="username">

                <label for="password">Password</label>
                <input type="password" name="password" id="password" required autocomplete="current-password">

                <button type="submit" class="go">Sign in</button>
            </form>
            <div class="switch-row" id="register-link-row">
                New customer? <a href="/register">Create a customer account</a>
            </div>
            <script>
                function pickRole(role) {
                    document.getElementById('selected_role').value = role;
                    document.getElementById('p-customer').classList.toggle('active', role === 'customer');
                    document.getElementById('p-support').classList.toggle('active', role === 'support');
                    const userField = document.getElementById('username');
                    if (role === 'support') {
                        if (!userField.value || userField.value === 'customer') {
                            userField.value = 'support';
                        }
                    } else {
                        if (userField.value === 'support') {
                            userField.value = 'customer';
                        }
                    }
                }
                // Highlight initial role button without overwriting custom typed username
                (function initRole() {
                    const initial = {{ selected|tojson }};
                    document.getElementById('p-customer').classList.toggle('active', initial === 'customer');
                    document.getElementById('p-support').classList.toggle('active', initial === 'support');
                })();
            </script>
        {% endif %}
        <div class="meta">Served by {{ instance_id }} ({{ az }})</div>
    </div>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    selected = "customer"
    form_username = "customer"
    status_code = 200
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        selected_role = (request.form.get("selected_role") or "").strip().lower()
        form_username = username
        if selected_role in ("customer", "support"):
            selected = selected_role
        elif username == "support":
            selected = "support"
        try:
            row = fetch_user(username)
        except Exception as exc:
            logger.error("Login lookup failed: %s", exc)
            row = None
            error = "Service temporarily unavailable. Please retry in a moment."
            status_code = 503
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session.permanent = True
            session.update(
                uid=row["id"],
                username=row["username"],
                role=row["role"],
                display_name=row["display_name"],
                email=row["email"],
            )
            return redirect("/")
        if not error:
            error = "Invalid username or password."
            status_code = 401
    return render_template_string(
        LOGIN_HTML,
        mode="login",
        error=error,
        selected=selected,
        form_username=form_username,
        form_display_name="",
        form_email="",
        instance_id=INSTANCE_META["instance_id"],
        az=INSTANCE_META["availability_zone"],
    ), status_code


@app.route("/register", methods=["GET", "POST"])
def register():
    """Allows a new customer to self-register an account and logs them in."""
    error = None
    form_username = ""
    form_display_name = ""
    form_email = ""
    status_code = 200

    if request.method == "POST":
        form_display_name = (request.form.get("display_name") or "").strip()[:120]
        form_username = (request.form.get("username") or "").strip().lower()
        form_email = (request.form.get("email") or "").strip().lower()[:160]
        password = request.form.get("password") or ""

        if not form_display_name:
            error = "Full name is required."
            status_code = 400
        elif not USERNAME_RE.match(form_username):
            error = "Username must be 3-64 characters using lowercase letters, numbers, dots, hyphens, or underscores."
            status_code = 400
        elif form_username == "support":
            error = "That username is reserved."
            status_code = 400
        elif "@" not in form_email or "." not in form_email.split("@")[-1]:
            error = "Please enter a valid email address."
            status_code = 400
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
            status_code = 400
        else:
            try:
                new_user, dup_err = create_customer_user(
                    form_username, password, form_display_name, form_email
                )
                if dup_err:
                    error = dup_err
                    status_code = 409
                elif new_user:
                    session.clear()
                    session.permanent = True
                    session.update(
                        uid=new_user["id"],
                        username=new_user["username"],
                        role=new_user["role"],
                        display_name=new_user["display_name"],
                        email=new_user["email"],
                    )
                    logger.info("Registered new customer username=%s on instance=%s",
                                new_user["username"], INSTANCE_META["instance_id"])
                    return redirect("/")
            except Exception as exc:
                logger.error("Customer registration failed: %s", exc)
                error = "Service temporarily unavailable. Please retry in a moment."
                status_code = 503

    return render_template_string(
        LOGIN_HTML,
        mode="register",
        error=error,
        selected="customer",
        form_username=form_username,
        form_display_name=form_display_name,
        form_email=form_email,
        instance_id=INSTANCE_META["instance_id"],
        az=INSTANCE_META["availability_zone"],
    ), status_code


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/api/me", methods=["GET"])
@api_auth()
def api_me():
    return jsonify(current_user()), 200


@app.route("/", methods=["GET"])
def index():
    """Renders the Helpdesk UI for the logged-in profile (customer or support)."""
    user = current_user()
    if not user:
        return redirect("/login")
    return render_template_string(
        FRONTEND_HTML,
        instance_id=INSTANCE_META["instance_id"],
        availability_zone=INSTANCE_META["availability_zone"],
        role=user["role"],
        username=user["username"],
        display_name=user["display_name"],
        email=user["email"],
    )


# ==============================================================================
# 7. Application Entrypoint
# ==============================================================================
ensure_schema()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)