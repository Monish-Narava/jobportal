from flask import Flask, render_template, request, redirect, session
import pymysql
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

# --------------------------------------
# APP CONFIG
# --------------------------------------
app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

serializer = URLSafeTimedSerializer(
    os.environ.get("SERIALIZER_KEY", "dev_serializer_key")
)

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")

# --------------------------------------
# DATABASE CONNECTION
# --------------------------------------
def get_connection():
    return pymysql.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", "root"),
        database=os.environ.get("DB_NAME", "jobportal"),
        cursorclass=pymysql.cursors.DictCursor
    )

# --------------------------------------
# HELPER: Get current logged-in user
# --------------------------------------
def get_current_user():
    if "user_id" not in session:
        return None
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

# --------------------------------------
# HOME
# --------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

# --------------------------------------
# REGISTER
# --------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
            (name, email, password, role)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

# --------------------------------------
# LOGIN
# --------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE email=%s AND password=%s",
            (email, password)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return "Invalid email or password"

        session['user_id'] = user['id']
        session['role'] = user['role']
        session['name'] = user['name']

        return redirect('/dashboard')
    return render_template('login.html')

# --------------------------------------
# FORGOT PASSWORD
# --------------------------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return render_template("forgot.html", message="Email not found!")

        token = serializer.dumps(email)
        reset_link = f"{BASE_URL}/reset-password/{token}"

        return render_template(
            "forgot.html",
            message="Reset link sent successfully!",
            reset_link=reset_link
        )

    return render_template('forgot.html')

# --------------------------------------
# RESET PASSWORD
# --------------------------------------
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, max_age=3600)
    except:
        return "Invalid or expired reset link!"

    if request.method == 'POST':
        new_password = request.form['password']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password=%s WHERE email=%s",
            (new_password, email)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return render_template("reset_done.html")

    return render_template("reset.html")

# --------------------------------------
# DASHBOARD
# --------------------------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    role = session.get("role")
    if role == "Job Seeker":
        return render_template("dashboard_student.html", user=session)
    elif role == "Employer":
        return render_template("dashboard_employer.html", user=session)
    return "Invalid role"

# --------------------------------------
# POST JOB
# --------------------------------------
@app.route('/job-post', methods=['GET', 'POST'])
def post_job():
    if 'user_id' not in session:
        return redirect('/login')
    if session['role'] != "Employer":
        return "Only employers can post jobs."

    if request.method == 'POST':
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO jobs (title, company, description, salary, location, posted_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            request.form['title'],
            request.form['company'],
            request.form['description'],
            request.form['salary'],
            request.form['location'],
            session['user_id']
        ))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect('/view-job')

    return render_template('job-post.html')

# --------------------------------------
# VIEW JOBS
# --------------------------------------
@app.route('/view-job')
def view_jobs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM jobs")
    jobs = cursor.fetchall()

    applied_job_ids = []
    if "user_id" in session and session.get("role") == "Job Seeker":
        cursor.execute(
            "SELECT job_id FROM applications WHERE user_id=%s",
            (session['user_id'],)
        )
        applied_job_ids = [j['job_id'] for j in cursor.fetchall()]

    cursor.close()
    conn.close()
    return render_template(
        'view-job.html',
        jobs=jobs,
        applied_job_ids=applied_job_ids
    )

# --------------------------------------
# LOGOUT
# --------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --------------------------------------
# RUN APP (RENDER READY)
# --------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
