from flask import Flask, render_template, request, redirect, session
import pymysql
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer("mysecretkey123")


app = Flask(__name__)
app.secret_key = "your_secret_key"

# --------------------------------------
# DATABASE CONNECTION
# --------------------------------------
def get_connection():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="root",
        database="jobportal",
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
        role = request.form['role']   # Job Seeker / Employer

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
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s",
                       (email, password))
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

        # Generate token
        token = serializer.dumps(email)

        # Fake email (show link on screen)
        reset_link = f"http://127.0.0.1:5000/reset-password/{token}"

        return render_template("forgot.html",
                               message="Reset link sent successfully!",
                               reset_link=reset_link)

    return render_template('forgot.html')
#---------------------------------------
#RESET PASSWORD
#---------------------------------------
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, max_age=3600)  # link valid for 1 hour
    except:
        return "Invalid or expired reset link!"

    if request.method == 'POST':
        new_password = request.form['password']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE email=%s",
                       (new_password, email))
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
    else:
        return "Invalid role value in database."

# --------------------------------------
# POST JOB (Employer Only)
# --------------------------------------
@app.route('/job-post', methods=['GET', 'POST'])
def post_job():
    if 'user_id' not in session:
        return redirect('/login')
    if session['role'] != "Employer":
        return "Only employers can post jobs."

    if request.method == 'POST':
        title = request.form['title']
        company = request.form['company']
        description = request.form['description']
        salary = request.form['salary']
        location = request.form['location']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO jobs 
            (title, company, description, salary, location, posted_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (title, company, description, salary, location, session['user_id']))
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
        cursor.execute("SELECT job_id FROM applications WHERE user_id=%s", (session['user_id'],))
        applied_jobs = cursor.fetchall()
        applied_job_ids = [job['job_id'] for job in applied_jobs]

    cursor.close()
    conn.close()
    return render_template('view-job.html', jobs=jobs, applied_job_ids=applied_job_ids)

# --------------------------------------
# ABOUT
# --------------------------------------
@app.route('/about')
def about():
    return render_template('about.html')

# --------------------------------------
# APPLY FOR JOB
# --------------------------------------
@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
def apply_job(job_id):
    if "user_id" not in session:
        return redirect("/login")
    if session['role'] != "Job Seeker":
        return "Only Job Seekers can apply for jobs."

    RESUME_FOLDER = "static/resumes"
    os.makedirs(RESUME_FOLDER, exist_ok=True)

    if request.method == "POST":
        resume = request.files["resume"]
        if resume.filename == "":
            return "Please upload a resume!"

        filename = secure_filename(resume.filename)
        filename = f"{session['user_id']}_{filename}"
        resume.save(os.path.join(RESUME_FOLDER, filename))

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO applications (user_id, job_id, resume)
            VALUES (%s, %s, %s)
        """, (session["user_id"], job_id, filename))
        conn.commit()
        cursor.close()
        conn.close()
        return "Resume Uploaded Successfully!"

    return render_template("apply.html", job_id=job_id)

# --------------------------------------
# VIEW APPLICATIONS
# --------------------------------------
@app.route('/view-applications')
def view_applications():
    if 'user_id' not in session:
        return redirect('/login')

    user = get_current_user()
    conn = get_connection()
    cursor = conn.cursor()

    if user['role'] == 'Job Seeker':
        cursor.execute("""
            SELECT applications.id, jobs.title, jobs.company, applications.resume
            FROM applications
            JOIN jobs ON applications.job_id = jobs.id
            WHERE applications.user_id = %s
        """, (user['id'],))
        applications = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('student-applications.html', applications=applications)
    else:
        cursor.execute("""
            SELECT applications.id, users.name, users.email, applications.resume, jobs.title
            FROM applications
            JOIN users ON applications.user_id = users.id
            JOIN jobs ON applications.job_id = jobs.id
            WHERE jobs.posted_by = %s
        """, (user['id'],))
        applications = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('employer-applications.html', applications=applications)

# --------------------------------------
# PROFILE & EDIT PROFILE
# --------------------------------------
UPLOAD_PROFILE = "static/profile_pics"
UPLOAD_RESUME = "static/resumes"
os.makedirs(UPLOAD_PROFILE, exist_ok=True)
os.makedirs(UPLOAD_RESUME, exist_ok=True)

@app.route("/profile")
def profile():
    user = get_current_user()
    if not user:
        return redirect("/login")
    if user["role"] == "Employer":
        return redirect("/employer/profile")
    return render_template("profile.html", user=user)

@app.route("/edit_profile")
def edit_profile():
    user = get_current_user()
    if not user:
        return redirect("/login")
    return render_template("edit_profile.html", user=user)

@app.route("/update_profile", methods=["POST"])
def update_profile():
    user = get_current_user()
    if not user:
        return redirect("/login")

    # Get form data
    form = request.form
    profile_pic = request.files.get("profile_pic")
    resume_file = request.files.get("resume_file")
    profile_pic_name = secure_filename(profile_pic.filename) if profile_pic else None
    resume_name = secure_filename(resume_file.filename) if resume_file else None

    if profile_pic_name:
        profile_pic.save(os.path.join(UPLOAD_PROFILE, profile_pic_name))
    if resume_name:
        resume_file.save(os.path.join(UPLOAD_RESUME, resume_name))

    conn = get_connection()
    cursor = conn.cursor()
    # Update fields dynamically
    update_query = """
        UPDATE users SET name=%s, email=%s, phone=%s, gender=%s, dob=%s,
        skills=%s, experience=%s, bio=%s, linkedin=%s, github=%s
    """
    params = [form.get("name"), form.get("email"), form.get("phone"), form.get("gender"),
              form.get("dob"), form.get("skills"), form.get("experience"), form.get("bio"),
              form.get("linkedin"), form.get("github")]

    if profile_pic_name:
        update_query += ", profile_pic=%s"
        params.append(profile_pic_name)
    if resume_name:
        update_query += ", resume_file=%s"
        params.append(resume_name)

    update_query += " WHERE id=%s"
    params.append(user["id"])

    cursor.execute(update_query, tuple(params))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect("/profile")

# --------------------------------------
# EMPLOYER PROFILE
# --------------------------------------
@app.route("/employer/profile")
def employer_profile():
    user = get_current_user()
    if not user:
        return redirect("/login")
    if user["role"] != "Employer":
        return redirect("/profile")
    return render_template("employer_profile.html", user=user)

@app.route("/employer/edit-profile")
def edit_employer_profile():
    user = get_current_user()
    if not user:
        return redirect("/login")
    if user["role"] != "Employer":
        return redirect("/profile")
    return render_template("employer_edit_profile.html", user=user)

# --------------------------------------
# LOGOUT
# --------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --------------------------------------
# RUN APP
# --------------------------------------
if __name__ == '__main__':
    app.run(debug=True) 
