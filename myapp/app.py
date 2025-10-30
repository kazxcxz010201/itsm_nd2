import logging
import os
import secrets
from urllib.parse import urljoin

import psycopg2
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
ACTIVE_SESSIONS = set()

app = Flask(__name__)

app.config["SECRET_KEY"] = "defaultkey"
app.config["WTF_CSRF_ENABLED"] = True
app.config["DATABASE_URL"] = os.environ.get("DATABASE_URL")

csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

oauth = OAuth(app)

oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="github",
    api_base_url="https://api.github.com/",
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    client_id=os.environ.get("GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),
    client_kwargs={"scope": "read:user user:email"},
)


def get_db():
    conn = psycopg2.connect(app.config["DATABASE_URL"])
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            force_logout BOOLEAN DEFAULT FALSE
        )
    """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_accounts (
            id SERIAL PRIMARY KEY,
            provider VARCHAR(50) NOT NULL,
            provider_user_id VARCHAR(255) NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(provider, provider_user_id)
        )
    """
    )
    conn.commit()
    conn.close()
    logger.info("tables created")


class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data and user_data.get("is_active", True):
        return User(user_data["id"], user_data["username"], user_data["email"])
    return None


@app.before_request
def check_force_logout():
    if current_user.is_authenticated:
        conn = get_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT force_logout FROM users WHERE id = %s", (current_user.id,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and user["force_logout"]:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET force_logout = FALSE WHERE id = %s",
                (current_user.id,),
            )
            conn.commit()
            conn.close()

            ACTIVE_SESSIONS.discard(current_user.id)
            logout_user()
            flash("Your session has been terminated by an administrator.", "warning")
            return redirect(url_for("login"))


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        password_repeat = request.form.get("password_repeat")

        if not username or not email or not password or not password_repeat:
            flash("All fields are required!", "danger")
            return redirect(url_for("signup"))

        if password != password_repeat:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))

        conn = get_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        if username.lower() == "admin":
            cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = 'admin'")
            if cursor.fetchone()["count"] > 0:
                flash(
                    "Admin account already exists! Please choose a different username.",
                    "danger",
                )
                conn.close()
                return redirect(url_for("signup"))

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            flash("Username already exists!", "danger")
            conn.close()
            return redirect(url_for("signup"))

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            flash("Email already registered!", "danger")
            conn.close()
            return redirect(url_for("signup"))

        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, password_hash),
        )
        conn.commit()
        conn.close()

        if username.lower() == "admin":
            flash("Admin account created successfully! Please log in.", "success")
        else:
            flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Please enter both username and password!", "danger")
            return redirect(url_for("login"))

        conn = get_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data and not user_data.get("is_active", True):
            flash("Your account has been deactivated by an administrator.", "danger")
            return redirect(url_for("login"))

        if user_data and check_password_hash(user_data["password_hash"], password):
            user = User(user_data["id"], user_data["username"], user_data["email"])
            login_user(user)
            ACTIVE_SESSIONS.add(user.id)

            if user.username.lower() == "admin":
                return redirect(url_for("admin"))

            return redirect(url_for("dashboard"))

        flash("Invalid username or password!", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


def redirect_uri_for(provider: str):
    base = os.environ.get("OAUTH_REDIRECT_BASE", request.host_url.rstrip("/"))
    return urljoin(base + "/", f"auth/{provider}/callback")


@app.route("/login/<provider>")
def oauth_login(provider):
    if provider not in ("google", "github"):
        flash("Unsupported provider", "danger")
        return redirect(url_for("login"))

    client = oauth.create_client(provider)

    if provider == "google":
        nonce = secrets.token_urlsafe(16)
        session["nonce"] = nonce
        return client.authorize_redirect(redirect_uri_for(provider), nonce=nonce)
    else:
        return client.authorize_redirect(redirect_uri_for(provider))


@app.route("/auth/<provider>/callback")
def oauth_callback(provider):
    client: OAuth2Session | None = oauth.create_client(provider)
    if client is None:
        flash("OAuth provider not configured.", "danger")
        return redirect(url_for("login"))

    token = client.authorize_access_token()

    user_info = {}

    if provider == "google":
        nonce = session.pop("nonce", None)
        user_info = client.parse_id_token(token, nonce=nonce)
        provider_user_id = user_info.get("sub")
        email = user_info.get("email")
        username = user_info.get("name") or email.split("@")[0]

    elif provider == "github":
        profile = client.get("user").json()
        emails = client.get("user/emails").json()
        email = profile.get("email") or next(
            (e["email"] for e in emails if e.get("primary")), None
        )
        provider_user_id = str(profile["id"])
        username = profile.get("login")

    return finish_oauth_login(provider, provider_user_id, email, username)


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.username.lower() == "admin":
        return redirect(url_for("admin"))
    return render_template("dashboard.html")


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        new_username = request.form.get("username")
        new_email = request.form.get("email")
        new_password = request.form.get("password")
        new_password_repeat = request.form.get("password_repeat")

        if not new_username or not new_email:
            flash("Username and email are required!", "danger")
            return redirect(url_for("edit_profile"))

        if current_user.username.lower() == "admin" and new_username != "admin":
            flash("Admin username cannot be changed!", "danger")
            return redirect(url_for("edit_profile"))

        if current_user.username.lower() != "admin" and new_username.lower() == "admin":
            flash('Cannot change username to "admin"!', "danger")
            return redirect(url_for("edit_profile"))

        conn = get_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        if new_username != current_user.username:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND id != %s",
                (new_username, current_user.id),
            )
            if cursor.fetchone():
                flash("Username already exists!", "danger")
                conn.close()
                return redirect(url_for("edit_profile"))

        if new_email != current_user.email:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s AND id != %s",
                (new_email, current_user.id),
            )
            if cursor.fetchone():
                flash("Email already registered!", "danger")
                conn.close()
                return redirect(url_for("edit_profile"))

        if new_password:
            if new_password != new_password_repeat:
                flash("Passwords do not match!", "danger")
                conn.close()
                return redirect(url_for("edit_profile"))

            password_hash = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET username = %s, email = %s, password_hash = %s WHERE id = %s",
                (new_username, new_email, password_hash, current_user.id),
            )
        else:
            cursor.execute(
                "UPDATE users SET username = %s, email = %s WHERE id = %s",
                (new_username, new_email, current_user.id),
            )

        conn.commit()
        conn.close()

        current_user.username = new_username
        current_user.email = new_email

        flash("Profile updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_profile.html")


@app.route("/admin")
@login_required
def admin():
    if current_user.username.lower() != "admin":
        flash("Access denied! Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT id, username, email, is_active FROM users ORDER BY id")
    users = cursor.fetchall()
    conn.close()

    return render_template("admin.html", users=users, active_sessions=ACTIVE_SESSIONS)


@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_edit_user(user_id):
    if current_user.username.lower() != "admin":
        flash("Access denied! Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == "POST":
        new_username = request.form.get("username")
        new_email = request.form.get("email")
        new_password = request.form.get("password")

        if not new_username or not new_email:
            flash("Username and email are required!", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        target_user = cursor.fetchone()

        if not target_user:
            flash("User not found!", "danger")
            conn.close()
            return redirect(url_for("admin"))

        if target_user["username"].lower() == "admin" and new_username != "admin":
            flash("Admin username cannot be changed!", "danger")
            conn.close()
            return redirect(url_for("admin_edit_user", user_id=user_id))

        cursor.execute(
            "SELECT * FROM users WHERE username = %s AND id != %s",
            (new_username, user_id),
        )
        if cursor.fetchone():
            flash("Username already exists!", "danger")
            conn.close()
            return redirect(url_for("admin_edit_user", user_id=user_id))

        cursor.execute(
            "SELECT * FROM users WHERE email = %s AND id != %s", (new_email, user_id)
        )
        if cursor.fetchone():
            flash("Email already registered!", "danger")
            conn.close()
            return redirect(url_for("admin_edit_user", user_id=user_id))

        if new_password:
            password_hash = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET username = %s, email = %s, password_hash = %s WHERE id = %s",
                (new_username, new_email, password_hash, user_id),
            )
        else:
            cursor.execute(
                "UPDATE users SET username = %s, email = %s WHERE id = %s",
                (new_username, new_email, user_id),
            )

        conn.commit()
        conn.close()

        flash("User updated successfully!", "success")
        return redirect(url_for("admin"))

    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("admin"))

    return render_template("admin_edit_user.html", user=user)


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    if current_user.username.lower() != "admin":
        flash("Access denied! Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    if user_id == current_user.id:
        flash("You cannot delete your own account!", "danger")
        return redirect(url_for("admin"))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        conn.close()
        return redirect(url_for("admin"))

    if user["username"].lower() == "admin":
        flash("Cannot delete admin account!", "danger")
        conn.close()
        return redirect(url_for("admin"))

    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()

    flash("User deleted successfully!", "success")
    return redirect(url_for("admin"))


@app.route("/admin/toggle_active/<int:user_id>", methods=["POST"])
@login_required
def admin_toggle_active(user_id):
    if current_user.username.lower() != "admin":
        flash("Access denied! Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "SELECT id, username, is_active FROM users WHERE id = %s", (user_id,)
    )
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        conn.close()
        return redirect(url_for("admin"))

    if user["username"].lower() == "admin":
        flash("Cannot deactivate the admin account!", "danger")
        conn.close()
        return redirect(url_for("admin"))

    new_state = not user["is_active"]
    if new_state:
        cursor.execute(
            "UPDATE users SET is_active = %s, force_logout = FALSE WHERE id = %s",
            (new_state, user_id),
        )
    else:
        cursor.execute(
            "UPDATE users SET is_active = %s WHERE id = %s",
            (new_state, user_id),
        )
    conn.commit()
    conn.close()

    flash(
        f"User '{user['username']}' has been {'reactivated' if new_state else 'deactivated'}.",
        "success",
    )
    return redirect(url_for("admin"))


@app.route("/admin/force_logout/<int:user_id>", methods=["POST"])
@login_required
def admin_force_logout(user_id):
    if current_user.username.lower() != "admin":
        flash("Access denied! Admin privileges required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET force_logout = TRUE WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()

    if user_id in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.remove(user_id)

    flash(f"User ID {user_id} has been force logged out.", "success")
    return redirect(url_for("admin"))


@app.route("/logout")
@login_required
def logout():
    ACTIVE_SESSIONS.discard(current_user.id)
    logout_user()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))


def finish_oauth_login(provider, provider_user_id, email, username):
    if not email:
        flash("Login failed: provider did not return an email", "danger")
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT u.* FROM users u
        JOIN oauth_accounts oa ON u.id = oa.user_id
        WHERE oa.provider=%s AND oa.provider_user_id=%s
        """,
        (provider, provider_user_id),
    )
    user = cur.fetchone()

    if not user:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user:
            password_hash = generate_password_hash(secrets.token_hex(16))
            cur.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                RETURNING *
                """,
                (username, email, password_hash),
            )
            user = cur.fetchone()

        cur.execute(
            """
            INSERT INTO oauth_accounts (provider, provider_user_id, user_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (provider, provider_user_id) DO NOTHING
            """,
            (provider, provider_user_id, user["id"]),
        )
        conn.commit()

    conn.close()

    if not user.get("is_active", True):
        flash("Your account has been deactivated by an administrator.", "danger")
        return redirect(url_for("login"))

    login_user(User(user["id"], user["username"], user["email"]))
    ACTIVE_SESSIONS.add(user["id"])
    flash(f"Logged in with {provider.capitalize()}", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()
    logger.info("START BY ME")
    app.run(host="0.0.0.0", port=5000, debug=True)
