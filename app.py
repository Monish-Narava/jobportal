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
        cursorclass=pymysql.cursors.DictCursor
    )

# ---------------- DB TEST ----------------
@app.route("/db-test")
def db_test():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return "✅ Database connected successfully"
    except Exception as e:
        return f"❌ DB Error: {e}"

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

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return "Email already exists"

        hashed_password = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s,%s,%s,%s)",
            (name, email, hashed_password, role)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user or not check_password_hash(user["password"], password):
            return "Invalid email or password"

        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["name"] = user["name"]

        return redirect("/dashboard")

    return render_template("login.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    if session["role"] == "Job Seeker":
        return render_template("dashboard_student.html", user=session)

    if session["role"] == "Employer":
        return render_template("dashboard_employer.html", user=session)

    return "Invalid role"

# ---------------- VIEW JOBS ----------------
@app.route("/jobs")
def view_jobs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM jobs")
    jobs = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("view-job.html", jobs=jobs)

# ---------------- POST JOB (EMPLOYER) ----------------
@app.route("/post-job", methods=["GET", "POST"])
def post_job():
    if "user_id" not in session or session["role"] != "Employer":
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        company = request.form["company"]
        description = request.form["description"]
        location = request.form["location"]
        salary = request.form["salary"]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO jobs (title, company, description, location, salary, employer_id) VALUES (%s,%s,%s,%s,%s,%s)",
            (title, company, description, location, salary, session["user_id"])
        )
        conn.commit()
        cursor.close()
        conn.close()

        return redirect("/dashboard")

    return render_template("job-post.html")

# ---------------- APPLY JOB ----------------
@app.route("/apply/<int:job_id>")
def apply_job(job_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO applications (job_id, user_id) VALUES (%s,%s)",
        (job_id, session["user_id"])
    )
    conn.commit()
    cursor.close()
    conn.close()

    return redirect("/my-applications")

# ---------------- STUDENT APPLICATIONS ----------------
@app.route("/my-applications")
def my_applications():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT jobs.title, jobs.company, applications.status
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.user_id = %s
    """, (session["user_id"],))
    apps = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("student-applications.html", applications=apps)

# ---------------- EMPLOYER APPLICATIONS ----------------
@app.route("/employer-applications")
def employer_applications():
    if "user_id" not in session or session["role"] != "Employer":
        return redirect("/login")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT users.name, users.email, jobs.title
        FROM applications
        JOIN users ON applications.user_id = users.id
        JOIN jobs ON applications.job_id = jobs.id
        WHERE jobs.employer_id = %s
    """, (session["user_id"],))
    apps = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("employer-applications.html", applications=apps)

# ---------------- PROFILE ----------------
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, role FROM users WHERE id=%s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template("profile.html", user=user)

# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return render_template("forgot.html", message="Email not found")

        token = serializer.dumps(email)
        reset_link = url_for("reset_password", token=token, _external=True)

        return render_template("forgot.html", message="Reset link generated", reset_link=reset_link)

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
        new_password = generate_password_hash(request.form["password"])

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (new_password, email))
        conn.commit()
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
    return redirect("/")

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

