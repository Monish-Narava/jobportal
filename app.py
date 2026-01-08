from flask import Flask, render_template, request, redirect, session, url_for
import pymysql
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ---------------- CONFIG ----------------
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

serializer = URLSafeTimedSerializer(
    os.environ.get("SERIALIZER_KEY", "dev_serializer_key")
)

# ---------------- DB CONNECTION ----------------
def get_connection():
    return pymysql.connect(
        host=os.environ.get("MYSQLHOST"),
        user=os.environ.get("MYSQLUSER"),
        password=os.environ.get("MYSQLPASSWORD"),
        database=os.environ.get("MYSQLDATABASE"),
        port=int(os.environ.get("MYSQLPORT", 3306)),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

# ---------------- HOME ----------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        conn = None
        cursor = None

        try:
            conn = get_connection()
            cursor = conn.cursor()

            # Check existing email
            cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
            if cursor.fetchone():
                return "Email already exists"

            hashed_password = generate_password_hash(password)

            cursor.execute(
                "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                (name, email, hashed_password, role)
            )
            conn.commit()

            return redirect("/login")

        except Exception as e:
            print("REGISTER ERROR:", e)
            return "Registration failed. Please try again."

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("register.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

        if not user or not check_password_hash(user["password"], password):
            return "Invalid email or password"

        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["name"] = user["name"]

        return redirect(url_for("dashboard"))

    return render_template("login.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] == "Job Seeker":
        return render_template("dashboard_student.html", user=session)

    if session["role"] == "Employer":
        return render_template("dashboard_employer.html", user=session)

    return "Invalid role"

# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

        if not user:
            return render_template("forgot.html", message="Email not found")

        token = serializer.dumps(email)
        reset_link = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        return render_template(
            "forgot.html",
            message="Reset link generated successfully",
            reset_link=reset_link
        )

    return render_template("forgot.html")

# ---------------- RESET PASSWORD ----------------
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        return "Reset link expired"
    except BadSignature:
        return "Invalid reset link"

    if request.method == "POST":
        new_password = generate_password_hash(request.form.get("password"))

        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE users SET password=%s WHERE email=%s",
                (new_password, email)
            )

        finally:
            cursor.close()
            conn.close()

        return render_template("reset_done.html")

    return render_template("reset.html")

# ---------------- ABOUT ----------------
@app.route("/about")
def about():
    return render_template("about.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

