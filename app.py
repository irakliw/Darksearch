# ============================================================
# DarkSearch Portal - app.py
# Flask + Turso
# Secure authentication / credits / payments / admin
# ============================================================

import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

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

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from dotenv import load_dotenv


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

# Turso may use HTTPS with a self-signed/intermediate cert
# in some environments. Keep warning disabled because
# verify=False is used below.
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# FLASK CONFIG
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.permanent_session_lifetime = timedelta(days=30)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Render is HTTPS in production.
# This automatically makes the session cookie secure there.
if os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"):
    app.config["SESSION_COOKIE_SECURE"] = True


# ============================================================
# TURSO CONFIG
# ============================================================

TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

if not TURSO_DATABASE_URL:
    raise RuntimeError(
        "TURSO_DATABASE_URL environment variable is missing."
    )

if not TURSO_AUTH_TOKEN:
    raise RuntimeError(
        "TURSO_AUTH_TOKEN environment variable is missing."
    )


# Convert:
# libsql://database-name.turso.io
#
# into:
# https://database-name.turso.io/v2/pipeline

TURSO_HTTP_URL = (
    TURSO_DATABASE_URL
    .replace("libsql://", "https://")
    .rstrip("/")
)

TURSO_PIPELINE_URL = TURSO_HTTP_URL + "/v2/pipeline"


# ============================================================
# TURSO EXECUTOR
# ============================================================

def turso_execute(sql, params=None):
    """
    Execute one SQL statement through Turso HTTP pipeline.

    IMPORTANT:
    All non-null bind parameters are sent as TEXT.
    Numeric values are explicitly CAST in SQL where necessary.

    This avoids the JSON integer parsing problem that was
    appearing in Render logs.
    """

    if params is None:
        params = []

    args = []

    for value in params:

        if value is None:
            args.append({
                "type": "null"
            })

        else:
            args.append({
                "type": "text",
                "value": str(value)
            })

    payload = {
        "requests": [
            {
                "type": "execute",
                "stmt": {
                    "sql": sql,
                    "args": args
                }
            }
        ]
    }

    try:

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

    except requests.RequestException as e:

        raise RuntimeError(
            f"Turso connection error: {e}"
        )

    if response.status_code != 200:

        raise RuntimeError(
            f"Turso HTTP error {response.status_code}: "
            f"{response.text}"
        )

    try:

        data = response.json()

    except Exception:

        raise RuntimeError(
            f"Turso returned invalid JSON: {response.text}"
        )

    results = data.get("results", [])

    if not results:

        raise RuntimeError(
            f"Turso returned no results: {data}"
        )

    first = results[0]

    if first.get("type") != "ok":

        raise RuntimeError(
            f"Turso query error: {first}"
        )

    response_data = first.get("response", {})

    result = response_data.get("result")

    if result is None:

        raise RuntimeError(
            f"Turso result missing: {first}"
        )

    return result


# ============================================================
# ROW HELPERS
# ============================================================

def turso_value(cell):

    """
    Convert Turso cell object into a normal Python value.
    """

    if cell is None:
        return None

    if isinstance(cell, dict):

        cell_type = cell.get("type")

        if cell_type == "null":
            return None

        return cell.get("value")

    return cell


def turso_rows(result):

    """
    Convert Turso rows into list of dictionaries.
    """

    columns = result.get("cols", [])
    rows = result.get("rows", [])

    column_names = []

    for column in columns:

        if isinstance(column, dict):
            column_names.append(
                column.get("name", "")
            )
        else:
            column_names.append(str(column))

    output = []

    for row in rows:

        values = [
            turso_value(cell)
            for cell in row
        ]

        item = {}

        for index, name in enumerate(column_names):

            if index < len(values):
                item[name] = values[index]
            else:
                item[name] = None

        output.append(item)

    return output


def as_int(value, default=0):

    try:
        return int(value)

    except (TypeError, ValueError):

        return default


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_app_tables():

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    turso_execute(
        """
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            credits INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    # --------------------------------------------------------
    # PURCHASE REQUESTS
    # --------------------------------------------------------

    turso_execute(
        """
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
            FOREIGN KEY(user_id)
                REFERENCES app_users(id)
        )
        """
    )

    # --------------------------------------------------------
    # NOTIFICATIONS
    # --------------------------------------------------------

    turso_execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            notification_type TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id)
                REFERENCES app_users(id)
        )
        """
    )

    # --------------------------------------------------------
    # SEARCH LOGS
    # --------------------------------------------------------

    turso_execute(
        """
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id)
                REFERENCES app_users(id)
        )
        """
    )

    print("[OK] Application tables ready")


# ============================================================
# ADMIN INITIALIZATION
# ============================================================

def ensure_admin():

    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_username or not admin_password:

        print(
            "[WARNING] ADMIN_USERNAME or ADMIN_PASSWORD "
            "is not configured."
        )

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

    rows = turso_rows(result)

    # --------------------------------------------------------
    # ADMIN ALREADY EXISTS
    # --------------------------------------------------------

    if rows:

        admin_id = as_int(rows[0].get("id"))

        turso_execute(
            """
            UPDATE app_users
            SET is_admin = CAST(? AS INTEGER)
            WHERE id = CAST(? AS INTEGER)
            """,
            ["1", str(admin_id)]
        )

        print("[OK] Admin account verified")

        return

    # --------------------------------------------------------
    # CREATE ADMIN
    # --------------------------------------------------------

    password_hash = generate_password_hash(
        admin_password
    )

    now = datetime.utcnow().isoformat()

    turso_execute(
        """
        INSERT INTO app_users (
            username,
            password_hash,
            credits,
            is_admin,
            created_at
        )
        VALUES (
            ?,
            ?,
            CAST(? AS INTEGER),
            CAST(? AS INTEGER),
            ?
        )
        """,
        [
            admin_username,
            password_hash,
            "999999999",
            "1",
            now
        ]
    )

    print("[OK] Admin account created")


# ============================================================
# CURRENT USER
# ============================================================

def current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    try:

        result = turso_execute(
            """
            SELECT
                id,
                username,
                password_hash,
                credits,
                is_admin,
                created_at
            FROM app_users
            WHERE id = CAST(? AS INTEGER)
            LIMIT 1
            """,
            [str(user_id)]
        )

        rows = turso_rows(result)

        if not rows:
            return None

        user = rows[0]

        user["id"] = as_int(user.get("id"))
        user["credits"] = as_int(user.get("credits"))
        user["is_admin"] = as_int(
            user.get("is_admin")
        )

        return user

    except Exception as e:

        print(
            "[CURRENT USER ERROR]",
            repr(e)
        )

        return None


# ============================================================
# LOGIN REQUIRED
# ============================================================

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        user = current_user()

        if not user:

            session.clear()

            flash(
                "გთხოვთ, ჯერ გაიაროთ ავტორიზაცია.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    return wrapped


# ============================================================
# ADMIN REQUIRED
# ============================================================

def admin_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        user = current_user()

        if not user:

            session.clear()

            return redirect(
                url_for("login")
            )

        if not user.get("is_admin"):

            flash(
                "ადმინისტრატორის უფლებები არ გაქვთ.",
                "danger"
            )

            return redirect(
                url_for("dashboard")
            )

        return view(*args, **kwargs)

    return wrapped


# ============================================================
# CONTEXT PROCESSOR
# ============================================================

@app.context_processor
def inject_globals():

    return {
        "current_user": current_user()
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    user = current_user()

    if user:

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "index.html"
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if current_user():

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = (
            request.form.get("username", "")
            .strip()
        )

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if len(username) < 3:

            flash(
                "მომხმარებლის სახელი მინიმუმ 3 სიმბოლო უნდა იყოს.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if len(username) > 50:

            flash(
                "მომხმარებლის სახელი ძალიან გრძელია.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if len(password) < 8:

            flash(
                "პაროლი მინიმუმ 8 სიმბოლო უნდა იყოს.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if password != confirm_password:

            flash(
                "პაროლები ერთმანეთს არ ემთხვევა.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # CHECK USER
        # ----------------------------------------------------

        try:

            result = turso_execute(
                """
                SELECT id
                FROM app_users
                WHERE username = ?
                LIMIT 1
                """,
                [username]
            )

            if turso_rows(result):

                flash(
                    "ეს მომხმარებლის სახელი უკვე დაკავებულია.",
                    "danger"
                )

                return render_template(
                    "register.html"
                )

            # ------------------------------------------------
            # CREATE USER
            # ------------------------------------------------

            password_hash = generate_password_hash(
                password
            )

            now = datetime.utcnow().isoformat()

            turso_execute(
                """
                INSERT INTO app_users (
                    username,
                    password_hash,
                    credits,
                    is_admin,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    CAST(? AS INTEGER),
                    CAST(? AS INTEGER),
                    ?
                )
                """,
                [
                    username,
                    password_hash,
                    "0",
                    "0",
                    now
                ]
            )

            flash(
                "რეგისტრაცია წარმატებით დასრულდა.",
                "success"
            )

            return redirect(
                url_for("login")
            )

        except Exception as e:

            print(
                "[REGISTER ERROR]",
                repr(e)
            )

            flash(
                "რეგისტრაციისას მოხდა შეცდომა.",
                "danger"
            )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if current_user():

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = (
            request.form.get("username", "")
            .strip()
        )

        password = request.form.get(
            "password",
            ""
        )

        try:

            result = turso_execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    credits,
                    is_admin
                FROM app_users
                WHERE username = ?
                LIMIT 1
                """,
                [username]
            )

            rows = turso_rows(result)

            if not rows:

                flash(
                    "მომხმარებელი ან პაროლი არასწორია.",
                    "danger"
                )

                return render_template(
                    "login.html"
                )

            user = rows[0]

            if not check_password_hash(
                user["password_hash"],
                password
            ):

                flash(
                    "მომხმარებელი ან პაროლი არასწორია.",
                    "danger"
                )

                return render_template(
                    "login.html"
                )

            session.clear()

            session.permanent = True

            session["user_id"] = as_int(
                user["id"]
            )

            session["username"] = user["username"]

            return redirect(
                url_for("dashboard")
            )

        except Exception as e:

            print(
                "[LOGIN ERROR]",
                repr(e)
            )

            flash(
                "ავტორიზაციისას მოხდა შეცდომა.",
                "danger"
            )

    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "თქვენ გამოხვედით სისტემიდან.",
        "success"
    )

    return redirect(
        url_for("index")
    )


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
#
# IMPORTANT:
# The underlying database contains highly sensitive personal
# information. Arbitrary public searching of those records is
# intentionally NOT enabled here.
#
# If you later implement an authorized/legitimate search flow,
# add strict access control, lawful-use restrictions,
# audit logging, rate limiting and field minimization.
# ============================================================

@app.route(
    "/api/search",
    methods=["POST"]
)
@login_required
def api_search():

    user = current_user()

    if not user:

        return jsonify({
            "success": False,
            "error": "ავტორიზაცია საჭიროა."
        }), 401

    if (
        user["credits"] <= 0
        and not user["is_admin"]
    ):

        return jsonify({
            "success": False,
            "error": "ძებნის კრედიტები არ გაქვთ."
        }), 403

    return jsonify({
        "success": False,
        "error": "საძიებო ფუნქცია ამ ეტაპზე გამორთულია."
    }), 501


# ============================================================
# PURCHASE PAGE
# ============================================================

@app.route("/purchase")
@login_required
def purchase_page():

    bank_account = os.getenv(
        "BANK_ACCOUNT",
        ""
    )

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

    return render_template(
        "purchase.html",
        bank_account=bank_account,
        packages=packages
    )


# ============================================================
# CREATE PURCHASE REQUEST
# ============================================================

@app.route(
    "/purchase",
    methods=["POST"]
)
@login_required
def purchase():

    user = current_user()

    package_id = (
        request.form.get("package", "")
        .strip()
    )

    sender_name = (
        request.form.get("sender_name", "")
        .strip()
    )

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

    if package_id not in packages:

        flash(
            "არასწორი პაკეტი.",
            "danger"
        )

        return redirect(
            url_for("purchase_page")
        )

    if not sender_name:

        flash(
            "მიუთითეთ გადამხდელის სახელი.",
            "danger"
        )

        return redirect(
            url_for("purchase_page")
        )

    package = packages[package_id]

    try:

        now = datetime.utcnow().isoformat()

        turso_execute(
            """
            INSERT INTO purchase_requests (
                user_id,
                username,
                sender_name,
                package_searches,
                amount,
                status,
                created_at
            )
            VALUES (
                CAST(? AS INTEGER),
                ?,
                ?,
                CAST(? AS INTEGER),
                CAST(? AS INTEGER),
                ?,
                ?
            )
            """,
            [
                str(user["id"]),
                user["username"],
                sender_name,
                str(package["searches"]),
                str(package["amount"]),
                "pending",
                now
            ]
        )

        flash(
            "გადახდის მოთხოვნა გაიგზავნა. "
            "ადმინისტრატორის დადასტურების შემდეგ "
            "კრედიტები დაგემატებათ.",
            "success"
        )

    except Exception as e:

        print(
            "[PURCHASE ERROR]",
            repr(e)
        )

        flash(
            "გადახდის მოთხოვნის შექმნისას მოხდა შეცდომა.",
            "danger"
        )

    return redirect(
        url_for("purchase_page")
    )


# ============================================================
# ADMIN PAGE
# ============================================================

@app.route("/admin")
@admin_required
def admin_page():

    try:

        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        users_result = turso_execute(
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

        users = turso_rows(
            users_result
        )

        for user in users:

            user["id"] = as_int(
                user.get("id")
            )

            user["credits"] = as_int(
                user.get("credits")
            )

            user["is_admin"] = as_int(
                user.get("is_admin")
            )

        # ----------------------------------------------------
        # PURCHASE REQUESTS
        # ----------------------------------------------------

        payments_result = turso_execute(
            """
            SELECT
                id,
                user_id,
                username,
                sender_name,
                package_searches,
                amount,
                status,
                created_at,
                processed_at
            FROM purchase_requests
            ORDER BY id DESC
            """
        )

        payments = turso_rows(
            payments_result
        )

        for payment in payments:

            payment["id"] = as_int(
                payment.get("id")
            )

            payment["user_id"] = as_int(
                payment.get("user_id")
            )

            payment["package_searches"] = as_int(
                payment.get("package_searches")
            )

            payment["amount"] = as_int(
                payment.get("amount")
            )

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        users_count_result = turso_execute(
            """
            SELECT COUNT(*) AS count
            FROM app_users
            """
        )

        users_count_rows = turso_rows(
            users_count_result
        )

        users_count = 0

        if users_count_rows:

            users_count = as_int(
                users_count_rows[0].get("count")
            )

        pending_count_result = turso_execute(
            """
            SELECT COUNT(*) AS count
            FROM purchase_requests
            WHERE status = ?
            """,
            ["pending"]
        )

        pending_count_rows = turso_rows(
            pending_count_result
        )

        pending_count = 0

        if pending_count_rows:

            pending_count = as_int(
                pending_count_rows[0].get("count")
            )

        approved_count_result = turso_execute(
            """
            SELECT COUNT(*) AS count
            FROM purchase_requests
            WHERE status = ?
            """,
            ["approved"]
        )

        approved_count_rows = turso_rows(
            approved_count_result
        )

        approved_count = 0

        if approved_count_rows:

            approved_count = as_int(
                approved_count_rows[0].get("count")
            )

        stats = {
            "users": users_count,
            "pending": pending_count,
            "approved": approved_count
        }

        return render_template(
            "admin.html",
            users=users,
            payments=payments,
            purchase_requests=payments,
            stats=stats
        )

    except Exception as e:

        print(
            "[ADMIN PAGE ERROR]",
            repr(e)
        )

        flash(
            "ადმინისტრატორის გვერდის ჩატვირთვისას მოხდა შეცდომა.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


# ============================================================
# APPROVE PAYMENT
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/approve",
    methods=["POST"]
)
@admin_required
def approve_payment(request_id):

    try:

        result = turso_execute(
            """
            SELECT
                id,
                user_id,
                package_searches,
                status
            FROM purchase_requests
            WHERE id = CAST(? AS INTEGER)
            LIMIT 1
            """,
            [str(request_id)]
        )

        rows = turso_rows(result)

        if not rows:

            flash(
                "გადახდის მოთხოვნა ვერ მოიძებნა.",
                "danger"
            )

            return redirect(
                url_for("admin_page")
            )

        payment = rows[0]

        status = payment.get("status")

        if status != "pending":

            flash(
                "ეს მოთხოვნა უკვე დამუშავებულია.",
                "warning"
            )

            return redirect(
                url_for("admin_page")
            )

        user_id = as_int(
            payment.get("user_id")
        )

        package_searches = as_int(
            payment.get("package_searches")
        )

        now = datetime.utcnow().isoformat()

        # ----------------------------------------------------
        # ADD CREDITS
        # ----------------------------------------------------

        turso_execute(
            """
            UPDATE app_users
            SET credits = credits + CAST(? AS INTEGER)
            WHERE id = CAST(? AS INTEGER)
            """,
            [
                str(package_searches),
                str(user_id)
            ]
        )

        # ----------------------------------------------------
        # MARK PAYMENT APPROVED
        # ----------------------------------------------------

        turso_execute(
            """
            UPDATE purchase_requests
            SET
                status = ?,
                processed_at = ?
            WHERE id = CAST(? AS INTEGER)
            """,
            [
                "approved",
                now,
                str(request_id)
            ]
        )

        # ----------------------------------------------------
        # NOTIFICATION
        # ----------------------------------------------------

        turso_execute(
            """
            INSERT INTO notifications (
                user_id,
                message,
                notification_type,
                is_read,
                created_at
            )
            VALUES (
                CAST(? AS INTEGER),
                ?,
                ?,
                CAST(? AS INTEGER),
                ?
            )
            """,
            [
                str(user_id),
                f"გადახდა დადასტურდა. "
                f"დაგემატათ {package_searches} კრედიტი.",
                "payment_approved",
                "0",
                now
            ]
        )

        flash(
            "გადახდა წარმატებით დადასტურდა.",
            "success"
        )

    except Exception as e:

        print(
            "[APPROVE ERROR]",
            repr(e)
        )

        flash(
            "გადახდის დადასტურებისას მოხდა შეცდომა.",
            "danger"
        )

    return redirect(
        url_for("admin_page")
    )


# ============================================================
# REJECT PAYMENT
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/reject",
    methods=["POST"]
)
@admin_required
def reject_payment(request_id):

    try:

        result = turso_execute(
            """
            SELECT
                id,
                user_id,
                status
            FROM purchase_requests
            WHERE id = CAST(? AS INTEGER)
            LIMIT 1
            """,
            [str(request_id)]
        )

        rows = turso_rows(result)

        if not rows:

            flash(
                "გადახდის მოთხოვნა ვერ მოიძებნა.",
                "danger"
            )

            return redirect(
                url_for("admin_page")
            )

        payment = rows[0]

        if payment.get("status") != "pending":

            flash(
                "ეს მოთხოვნა უკვე დამუშავებულია.",
                "warning"
            )

            return redirect(
                url_for("admin_page")
            )

        user_id = as_int(
            payment.get("user_id")
        )

        now = datetime.utcnow().isoformat()

        # ----------------------------------------------------
        # REJECT
        # ----------------------------------------------------

        turso_execute(
            """
            UPDATE purchase_requests
            SET
                status = ?,
                processed_at = ?
            WHERE id = CAST(? AS INTEGER)
            """,
            [
                "rejected",
                now,
                str(request_id)
            ]
        )

        # ----------------------------------------------------
        # NOTIFICATION
        # ----------------------------------------------------

        turso_execute(
            """
            INSERT INTO notifications (
                user_id,
                message,
                notification_type,
                is_read,
                created_at
            )
            VALUES (
                CAST(? AS INTEGER),
                ?,
                ?,
                CAST(? AS INTEGER),
                ?
            )
            """,
            [
                str(user_id),
                "გადახდის მოთხოვნა უარყოფილია.",
                "payment_rejected",
                "0",
                now
            ]
        )

        flash(
            "გადახდის მოთხოვნა უარყოფილია.",
            "success"
        )

    except Exception as e:

        print(
            "[REJECT ERROR]",
            repr(e)
        )

        flash(
            "მოთხოვნის უარყოფისას მოხდა შეცდომა.",
            "danger"
        )

    return redirect(
        url_for("admin_page")
    )


# ============================================================
# NOTIFICATIONS API
# ============================================================

@app.route(
    "/api/notifications",
    methods=["GET"]
)
@login_required
def api_notifications():

    user = current_user()

    if not user:

        return jsonify({
            "success": False,
            "error": "ავტორიზაცია საჭიროა."
        }), 401

    try:

        result = turso_execute(
            """
            SELECT
                id,
                message,
                notification_type,
                is_read,
                created_at
            FROM notifications
            WHERE user_id = CAST(? AS INTEGER)
            ORDER BY id DESC
            LIMIT 20
            """,
            [str(user["id"])]
        )

        notifications = turso_rows(
            result
        )

        for notification in notifications:

            notification["id"] = as_int(
                notification.get("id")
            )

            notification["is_read"] = as_int(
                notification.get("is_read")
            )

        return jsonify({
            "success": True,
            "notifications": notifications
        })

    except Exception as e:

        print(
            "[NOTIFICATIONS ERROR]",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": "შეტყობინებების ჩატვირთვა ვერ მოხერხდა."
        }), 500


# ============================================================
# MARK NOTIFICATION AS READ
# ============================================================

@app.route(
    "/api/notifications/<int:notification_id>/read",
    methods=["POST"]
)
@login_required
def mark_notification_read(notification_id):

    user = current_user()

    if not user:

        return jsonify({
            "success": False
        }), 401

    try:

        turso_execute(
            """
            UPDATE notifications
            SET is_read = CAST(? AS INTEGER)
            WHERE id = CAST(? AS INTEGER)
              AND user_id = CAST(? AS INTEGER)
            """,
            [
                "1",
                str(notification_id),
                str(user["id"])
            ]
        )

        return jsonify({
            "success": True
        })

    except Exception as e:

        print(
            "[NOTIFICATION READ ERROR]",
            repr(e)
        )

        return jsonify({
            "success": False
        }), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    try:

        result = turso_execute(
            "SELECT 1 AS test"
        )

        rows = turso_rows(result)

        return jsonify({
            "status": "ok",
            "database": True,
            "test": rows
        })

    except Exception as e:

        print(
            "[HEALTH ERROR]",
            repr(e)
        )

        return jsonify({
            "status": "error",
            "database": False
        }), 500


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return render_template(
        "index.html"
    ), 404


@app.errorhandler(500)
def internal_error(error):

    print(
        "[500 ERROR]",
        repr(error)
    )

    return """
    <!DOCTYPE html>
    <html lang="ka">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">
        <title>DarkSearch - Error</title>
        <style>
            body {
                margin: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: #050505;
                color: white;
                font-family: Arial, sans-serif;
                text-align: center;
            }

            .box {
                padding: 40px;
                border: 1px solid rgba(255,255,255,.1);
                border-radius: 24px;
                background: rgba(255,255,255,.04);
                backdrop-filter: blur(20px);
            }

            h1 {
                color: #d4af37;
            }

            a {
                color: #d4af37;
                text-decoration: none;
            }
        </style>
    </head>

    <body>

        <div class="box">

            <h1>500</h1>

            <p>
                სერვერზე დროებითი შეცდომა მოხდა.
            </p>

            <a href="/">
                მთავარ გვერდზე დაბრუნება
            </a>

        </div>

    </body>
    </html>
    """, 500


# ============================================================
# STARTUP
# ============================================================

try:

    initialize_app_tables()

    ensure_admin()

    print(
        "[OK] Turso connection established"
    )

except Exception as e:

    print(
        "[ERROR] Startup database initialization failed:"
    )

    print(
        repr(e)
    )


# ============================================================
# LOCAL RUN
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
        debug=False
    )
