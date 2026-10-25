import json
import os
import time
import urllib.request

eximport boto3
import pymysql
import pymysql.cursors
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

DB_HOST = os.environ["DB_HOST"]
DB_NAME = os.environ.get("DB_NAME", "todo_db")
SECRET_ARN = os.environ["DB_SECRET_ARN"]
REGION = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")

_creds = None
_table_ready = False


def get_credentials(refresh=False):
    """Read DB username/password from Secrets Manager (never from code)."""
    global _creds
    if _creds is None or refresh:
        client = boto3.client("secretsmanager", region_name=REGION)
        secret = client.get_secret_value(SecretId=SECRET_ARN)
        _creds = json.loads(secret["SecretString"])
    return _creds


def get_conn(retries=4):
    """Open a connection with retries so RDS failover doesn't crash requests."""
    last_err = None
    for attempt in range(retries):
        try:
            c = get_credentials(refresh=(attempt > 0))
            return pymysql.connect(
                host=DB_HOST,
                user=c["username"],
                password=c["password"],
                database=DB_NAME,
                connect_timeout=5,
                autocommit=True,
                cursorclass=pymysql.cursors.DictCursor,
            )
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2 ** attempt * 0.5)
    raise last_err


def ensure_table():
    global _table_ready
    if _table_ready:
        return
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """CREATE TABLE IF NOT EXISTS tasks (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    completed TINYINT(1) NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )"""
            )
        _table_ready = True
    finally:
        conn.close()


def run(query, params=None, fetch=None):
    ensure_table()
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params or ())
            if fetch == "all":
                return cur.fetchall()
            if fetch == "id":
                return cur.lastrowid
            return cur.rowcount
    finally:
        conn.close()


def imds(path):
    """Instance metadata (IMDSv2). Used to show which server answered."""
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        token = urllib.request.urlopen(req, timeout=1).read().decode()
        req = urllib.request.Request(
            f"http://169.254.169.254/latest/meta-data/{path}",
            headers={"X-aws-ec2-metadata-token": token})
        return urllib.request.urlopen(req, timeout=1).read().decode()
    except Exception:  # noqa: BLE001
        return "unknown"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    # Lightweight on purpose: does NOT touch the DB, so a DB failover
    # doesn't make the ALB mark every instance unhealthy.
    return jsonify(status="ok"), 200


@app.route("/health/db")
def health_db():
    try:
        run("SELECT 1", fetch="all")
        return jsonify(status="ok", db="up"), 200
    except Exception as e:  # noqa: BLE001
        return jsonify(status="degraded", db=str(e)), 503


@app.route("/api/info")
def info():
    return jsonify(instance_id=imds("instance-id"),
                   az=imds("placement/availability-zone"))


@app.route("/api/tasks", methods=["GET"])
def list_tasks():
    return jsonify(run("SELECT * FROM tasks ORDER BY id DESC", fetch="all"))


@app.route("/api/tasks", methods=["POST"])
def add_task():
    title = (request.json or {}).get("title", "").strip()
    if not title:
        return jsonify(error="title required"), 400
    new_id = run("INSERT INTO tasks (title) VALUES (%s)", (title,), fetch="id")
    return jsonify(id=new_id, title=title, completed=0), 201


@app.route("/api/tasks/<int:task_id>", methods=["PUT"])
def update_task(task_id):
    data = request.json or {}
    if "title" in data:
        run("UPDATE tasks SET title=%s WHERE id=%s", (data["title"], task_id))
    if "completed" in data:
        run("UPDATE tasks SET completed=%s WHERE id=%s",
            (1 if data["completed"] else 0, task_id))
    return jsonify(ok=True)


@app.route("/api/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    run("DELETE FROM tasks WHERE id=%s", (task_id,))
    return jsonify(ok=True)


@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception(e)
    return jsonify(error="temporary server error, please retry"), 503