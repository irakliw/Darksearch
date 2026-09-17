import os
import sqlite3
import secrets
from datetime import datetime, timedelta

import requests
import urllib3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)

from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv


# ============================================================
# CONFIG
# ============================================================

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()

if not TURSO_DATABASE_URL:
    raise RuntimeError("TURSO_DATABASE_URL is missing")

if not TURSO_AUTH_TOKEN:
    raise RuntimeError("TURSO_AUTH_TOKEN is missing")


# ============================================================
# TURSO
# ============================================================

TURSO_HTTP_URL = TURSO_DATABASE_URL.replace(
    "libsql://",
    "https://"
).rstrip("/")

TURSO_PIPELINE_URL = TURSO_HTTP_URL + "/v2/pipeline"


def turso_execute(sql, params=None):
    """
    Executes one SQL statement through Turso HTTP API.

    params example:
        ["gela", "hash"]
    """

    if params is None:
        params = []

    payload = {
        "requests": [
            {
                "type": "execute",
                "stmt": {
                    "sql": sql,
                    "args": [
                        {"type": "text", "value": str(x)}
                        if x is not None
                        else {"type": "null"}
                        for x in params
                    ]
                }
            }
        ]
    }

    response = requests.post(
        TURSO_PIPELINE_URL,
        headers={
            "Authorization": f"Bearer {TURSO_AUTH_TOKEN}",
            "Content-Type": "application/json"
        },
        json=payload,
        timeout=30,
        verify=False
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Turso HTTP error {response.status_code}: "
            f"{response.text}"
        )

    data = response.json()

    results = data.get("results", [])

    if not results:
        raise RuntimeError("Turso returned no results")

    first = results[0]

    if first.get("type") != "ok":
        raise RuntimeError(str(first))

    result = first["response"]["result"]

    return result


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_app_tables():

    # Users
    turso_execute("""
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            credits INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # Purchase requests
    turso_execute("""
        CREATE TABLE IF NOT EXISTS purchase_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            sender_name TEXT NOT NULL,
            package_searches INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            processed_at TEXT,
            FOREIGN KEY(user_id) REFERENCES app_users(id)
        )
    """)

    # Notifications
    turso_execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            notification_type TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES app_users(id)
        )
    """)

    # Search logs
    turso_execute("""
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES app_users(id)
        )
    """)


# ============================================================
# ADMIN
# ============================================================

def ensure_admin():

    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_username or not admin_password:
        print("[WARNING] ADMIN_USERNAME / ADMIN_PASSWORD not configured")
        return

    result = turso_execute(
        """
        SELECT id
        FROM app_users
        WHERE username = ?
        LIMIT 1
        """,
        [admin_username]
    )

    rows = result.get("rows", [])

    if rows:
        return

    password_hash = generate_password_hash(
        admin_password
    )

    turso_execute(
        """
        INSERT INTO app_users
        (
            username,
            password_hash,
            credits,
            is_admin,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            admin_username,
            password_hash,
            999999999,
            1,
            datetime.utcnow().isoformat()
        ]
    )

    print("[OK] Admin account created")


# ============================================================
# HELPERS
# ============================================================

def current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    result = turso_execute(
        """
        SELECT
            id,
            username,
            credits,
            is_admin
        FROM app_users
        WHERE id = ?
        LIMIT 1
        """,
        [user_id]
    )

    rows = result.get("rows", [])

    if not rows:
        session.clear()
        return None

    row = rows[0]

    return {
        "id": int(row[0]["value"]),
        "username": row[1]["value"],
        "credits": int(row[2]["value"]),
        "is_admin": int(row[3]["value"])
    }


def login_required(view):

    def wrapped(*args, **kwargs):

        user = current_user()

        if not user:
            flash("გთხოვთ, ჯერ შეხვიდეთ ანგარიშში.", "warning")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__

    return wrapped


def admin_required(view):

    def wrapped(*args, **kwargs):

        user = current_user()

        if not user or not user["is_admin"]:
            return redirect(url_for("dashboard"))

        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__

    return wrapped


# ============================================================
# CONTEXT
# ============================================================

@app.context_processor
def inject_user():

    return {
        "current_user": current_user()
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    if current_user():
        return redirect(url_for("dashboard"))

    return render_template("index.html")


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(username) < 3:
            flash(
                "მომხმარებლის სახელი მინიმუმ 3 სიმბოლო უნდა იყოს.",
                "danger"
            )
            return redirect(url_for("register"))

        if len(password) < 8:
            flash(
                "პაროლი მინიმუმ 8 სიმბოლო უნდა იყოს.",
                "danger"
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash(
                "პაროლები ერთმანეთს არ ემთხვევა.",
                "danger"
            )
            return redirect(url_for("register"))

        result = turso_execute(
            """
            SELECT id
            FROM app_users
            WHERE username = ?
            LIMIT 1
            """,
            [username]
        )

        if result.get("rows"):
            flash(
                "ეს მომხმარებლის სახელი უკვე დაკავებულია.",
                "danger"
            )
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        turso_execute(
            """
            INSERT INTO app_users
            (
                username,
                password_hash,
                credits,
                is_admin,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                username,
                password_hash,
                0,
                0,
                datetime.utcnow().isoformat()
            ]
        )

        flash(
            "ანგარიში წარმატებით შეიქმნა. ახლა შედით.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        result = turso_execute(
            """
            SELECT
                id,
                username,
                password_hash,
                is_admin
            FROM app_users
            WHERE username = ?
            LIMIT 1
            """,
            [username]
        )

        rows = result.get("rows", [])

        if not rows:
            flash(
                "მომხმარებელი ან პაროლი არასწორია.",
                "danger"
            )
            return redirect(url_for("login"))

        row = rows[0]

        user_id = int(row[0]["value"])
        db_username = row[1]["value"]
        password_hash = row[2]["value"]

        if not check_password_hash(
            password_hash,
            password
        ):
            flash(
                "მომხმარებელი ან პაროლი არასწორია.",
                "danger"
            )
            return redirect(url_for("login"))

        session.clear()

        session["user_id"] = user_id
        session["username"] = db_username

        session.permanent = True

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("index"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    return render_template(
        "dashboard.html",
        user=user
    )


# ============================================================
# SEARCH PAGE
# ============================================================

@app.route("/search")
@login_required
def search():

    user = current_user()

    return render_template(
        "search.html",
        user=user
    )


# ============================================================
# SEARCH API
# ============================================================

@app.route("/api/search", methods=["POST"])
@login_required
def api_search():

    user = current_user()

    # Search is intentionally not connected to the
    # personal-data table in this version.
    #
    # The endpoint only demonstrates authentication
    # and credit validation.

    if user["credits"] <= 0 and not user["is_admin"]:

        return jsonify({
            "success": False,
            "error": "ძებნის კრედიტები არ გაქვთ."
        }), 403

    return jsonify({
        "success": False,
        "error": "საძიებო ფუნქცია ჯერ არ არის ჩართული."
    }), 501


# ============================================================
# PURCHASE PAGE
# ============================================================

@app.route("/purchase")
@login_required
def purchase():

    return render_template(
        "purchase.html"
    )


# ============================================================
# PURCHASE REQUEST
# ============================================================

@app.route("/purchase/request", methods=["POST"])
@login_required
def purchase_request():

    user = current_user()

    package = request.form.get(
        "package",
        ""
    )

    sender_name = request.form.get(
        "sender_name",
        ""
    ).strip()

    packages = {
        "1": {
            "searches": 1,
            "amount": 2
        },
        "2": {
            "searches": 2,
            "amount": 3
        },
        "5": {
            "searches": 5,
            "amount": 8
        }
    }

    if package not in packages:

        flash(
            "არასწორი პაკეტი.",
            "danger"
        )

        return redirect(url_for("purchase"))

    if not sender_name:

        flash(
            "მიუთითეთ გადმომრიცხავის სახელი და გვარი.",
            "danger"
        )

        return redirect(url_for("purchase"))

    selected = packages[package]

    turso_execute(
        """
        INSERT INTO purchase_requests
        (
            user_id,
            username,
            sender_name,
            package_searches,
            amount,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            user["id"],
            user["username"],
            sender_name,
            selected["searches"],
            selected["amount"],
            "pending",
            datetime.utcnow().isoformat()
        ]
    )

    flash(
        "მოთხოვნა გაიგზავნა ადმინისტრატორთან.",
        "success"
    )

    return redirect(url_for("purchase"))


# ============================================================
# ADMIN PANEL
# ============================================================

@app.route("/admin")
@admin_required
def admin():

    result = turso_execute(
        """
        SELECT
            id,
            username,
            credits,
            is_admin,
            created_at
        FROM app_users
        ORDER BY id DESC
        """
    )

    users = []

    for row in result.get("rows", []):

        users.append({
            "id": int(row[0]["value"]),
            "username": row[1]["value"],
            "credits": int(row[2]["value"]),
            "is_admin": int(row[3]["value"]),
            "created_at": row[4]["value"]
        })

    requests_result = turso_execute(
        """
        SELECT
            id,
            user_id,
            username,
            sender_name,
            package_searches,
            amount,
            status,
            created_at
        FROM purchase_requests
        ORDER BY id DESC
        """
    )

    purchase_requests = []

    for row in requests_result.get("rows", []):

        purchase_requests.append({
            "id": int(row[0]["value"]),
            "user_id": int(row[1]["value"]),
            "username": row[2]["value"],
            "sender_name": row[3]["value"],
            "searches": int(row[4]["value"]),
            "amount": int(row[5]["value"]),
            "status": row[6]["value"],
            "created_at": row[7]["value"]
        })

    return render_template(
        "admin.html",
        users=users,
        purchase_requests=purchase_requests
    )


# ============================================================
# ADMIN APPROVE
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/approve",
    methods=["POST"]
)
@admin_required
def approve_request(request_id):

    result = turso_execute(
        """
        SELECT
            user_id,
            package_searches,
            status
        FROM purchase_requests
        WHERE id = ?
        LIMIT 1
        """,
        [request_id]
    )

    rows = result.get("rows", [])

    if not rows:
        flash(
            "მოთხოვნა ვერ მოიძებნა.",
            "danger"
        )
        return redirect(url_for("admin"))

    row = rows[0]

    user_id = int(row[0]["value"])
    searches = int(row[1]["value"])
    status = row[2]["value"]

    if status != "pending":

        flash(
            "ეს მოთხოვნა უკვე დამუშავებულია.",
            "warning"
        )

        return redirect(url_for("admin"))

    turso_execute(
        """
        UPDATE app_users
        SET credits = credits + ?
        WHERE id = ?
        """,
        [
            searches,
            user_id
        ]
    )

    turso_execute(
        """
        UPDATE purchase_requests
        SET
            status = 'approved',
            processed_at = ?
        WHERE id = ?
        """,
        [
            datetime.utcnow().isoformat(),
            request_id
        ]
    )

    turso_execute(
        """
        INSERT INTO notifications
        (
            user_id,
            message,
            notification_type,
            is_read,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            user_id,
            f"ადმინისტრატორმა თქვენი მოთხოვნა დაადასტურა. დაგემატათ {searches} კრედიტი.",
            "success",
            0,
            datetime.utcnow().isoformat()
        ]
    )

    flash(
        "მოთხოვნა დადასტურდა.",
        "success"
    )

    return redirect(url_for("admin"))


# ============================================================
# ADMIN REJECT
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/reject",
    methods=["POST"]
)
@admin_required
def reject_request(request_id):

    result = turso_execute(
        """
        SELECT user_id, status
        FROM purchase_requests
        WHERE id = ?
        LIMIT 1
        """,
        [request_id]
    )

    rows = result.get("rows", [])

    if not rows:

        flash(
            "მოთხოვნა ვერ მოიძებნა.",
            "danger"
        )

        return redirect(url_for("admin"))

    user_id = int(rows[0][0]["value"])
    status = rows[0][1]["value"]

    if status != "pending":

        flash(
            "ეს მოთხოვნა უკვე დამუშავებულია.",
            "warning"
        )

        return redirect(url_for("admin"))

    turso_execute(
        """
        UPDATE purchase_requests
        SET
            status = 'rejected',
            processed_at = ?
        WHERE id = ?
        """,
        [
            datetime.utcnow().isoformat(),
            request_id
        ]
    )

    turso_execute(
        """
        INSERT INTO notifications
        (
            user_id,
            message,
            notification_type,
            is_read,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            user_id,
            "ადმინისტრატორმა თქვენი მოთხოვნა უარყო.",
            "error",
            0,
            datetime.utcnow().isoformat()
        ]
    )

    flash(
        "მოთხოვნა უარყოფილია.",
        "success"
    )

    return redirect(url_for("admin"))


# ============================================================
# NOTIFICATIONS
# ============================================================

@app.route("/api/notifications")
@login_required
def notifications():

    user = current_user()

    result = turso_execute(
        """
        SELECT
            id,
            message,
            notification_type,
            is_read,
            created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 20
        """,
        [user["id"]]
    )

    notifications_list = []

    for row in result.get("rows", []):

        notifications_list.append({
            "id": int(row[0]["value"]),
            "message": row[1]["value"],
            "type": row[2]["value"],
            "is_read": int(row[3]["value"]),
            "created_at": row[4]["value"]
        })

    return jsonify({
        "success": True,
        "notifications": notifications_list
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    try:

        result = turso_execute(
            "SELECT 1 AS test"
        )

        return jsonify({
            "status": "ok",
            "database": True
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "database": False
        }), 500


# ============================================================
# STARTUP
# ============================================================

with app.app_context():

    try:

        initialize_app_tables()
        ensure_admin()

        print("[OK] Turso connection established")
        print("[OK] Application tables ready")

    except Exception as e:

        print("[ERROR] Startup database initialization failed:")
        print(e)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
