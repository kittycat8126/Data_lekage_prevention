from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os
from werkzeug.utils import secure_filename
from functools import wraps
from flask import flash, get_flashed_messages
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer


EMAIL_SENDER = "dlpfromvinay@gmail.com"
EMAIL_PASSWORD = "ukdb bprx zyop zvgv"  # use Gmail App Password

app = Flask(__name__)
app.secret_key = "Hola-amigo$DollarSignOneTime"


#token - generator
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset-salt')


# token verification 
def verify_reset_token(token, expiration=3600):  # 1 hour expiry
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return None
    return email


# password reset mail sender 
def send_reset_email(email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    subject = "Reset Your Password"
    body = f"Click the link to reset your password: {reset_link}"

    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@gmail.com'
    msg['To'] = email

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login('your_email@gmail.com', 'your_app_password')
    server.send_message(msg)
    server.quit()






#Access control matrix 
ACM = {
    "user":  {"view": True, "upload": True,  "admin": False},
    "admin": {"view": True, "upload": True,  "admin": True}
}

# --- Upload folder config ---
UPLOAD_FOLDER = os.path.join('static','uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# to prevent malicious file exicution on site
ALLOWED_EXTENSIONS = {"txt", "pdf", "docx"}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# DATABASE SETUP
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# 🔐 Permission control (boolean-style)
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            role = session.get("role")
            if not role or not ACM.get(role, {}).get(permission, False):
                return "⛔ Access Denied: You don't have permission for this action.", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Upload route ---
@app.route("/upload", methods=["GET", "POST"])
@permission_required("upload")
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("⚠️ No file part in the form", "error")
            return redirect(url_for("upload"))

        file = request.files["file"]
        if file.filename == "":
            flash("⚠️ No selected file", "error")
            return redirect(url_for("upload"))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            flash(f"✅ File {filename} uploaded successfully!", "success")
            return redirect(url_for("upload"))
        else:
            flash("⛔ File type not allowed", "error")
            return redirect(url_for("upload"))

    return render_template("upload.html")



#admin route
@app.route("/admin")
def admin():
    if "role" not in session or session["role"] != "admin":
        return "Access denied. Admins only."

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, role FROM users")
    users = c.fetchall()
    conn.close()

    # Get uploaded files
    files = os.listdir(app.config["UPLOAD_FOLDER"])

    return render_template("admin.html", users=users, files=files)


#forgot password route 
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        token = generate_reset_token(email)
        send_reset_email(email, token)
        return "Reset link sent!"
    return render_template('forgot_password.html')


#reset password token route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        return "Invalid or expired token."

    if request.method == 'POST':
        new_password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
        conn.commit()
        conn.close()
        return "Password reset successfully."

    return render_template('reset_password.html', token=token)



#----admin route to access uploaded files
@app.route("/admin/files")
@permission_required("upload")  # or use "view_files" if you separate permissions
def view_uploaded_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template("uploadedfiles.html", files=files)

# register route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        role = request.form.get("role", "user")

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, password, role))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except:
            return "User already exists or error occurred."

    return render_template("register.html")


#login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[4]
            return redirect(url_for("index"))
        else:
            return "Invalid email or password."

    return render_template("login.html")
    ...


#logout route 
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

#--app route for files
@app.route("/files")
@permission_required("view_files")  # OR restrict manually to admins
def view_files():
    if session.get("role") != "admin":
        return "Access denied", 403

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template("files.html", files=files)


# --- Breach Check Function ---
def check_email_breach(email):
    url = "https://breachdirectory.p.rapidapi.com/"
    querystring = {"func": "auto", "term": email}

    headers = {
        "X-RapidAPI-Key": "407656d08bmsh227f2ab0860bceap1c13e1jsn2af49864f44f",  # 🔐 Your actual key
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }

    try:
        res = requests.get(url, headers=headers, params=querystring)
        data = res.json()
        print(f"[RapidAPI] Response: {data}")  # Debug log

        if data.get("success") and data.get("result"):
            breaches = [
                line.split(":")[0] + ": ********"
                for line in data['result'][:5]
            ]
            return True, breaches
        elif data.get("success"):
            return False, []
        else:
            return False, ["API Error"]
    except Exception as e:
        print(f"[ERROR] {e}")
        return False, [str(e)]

# --- Route Setup ---
@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return render_template("index.html",not_logged_in=True)
    if request.method == "POST":
        email = request.form.get("email")
        phone = request.form.get("phone")

        email_leaked, email_breaches = check_email_breach(email)

        # Mock phone leak logic
        if phone and phone.endswith("1234"):
            phone_leaked = True
            phone_breaches = ["MockPhoneLeakSource"]
        else:
            phone_leaked = False
            phone_breaches = []

        return render_template("index.html",
                               email=email,
                               email_leaked=email_leaked,
                               email_breaches=email_breaches,
                               phone=phone,
                               phone_leaked=phone_leaked,
                               phone_breaches=phone_breaches)

    return render_template("index.html")

#role -update route
@app.route("/update_role", methods=["POST"])
@permission_required("admin")
def update_role():
    user_id = request.form["user_id"]
    new_role = request.form["new_role"]
    admin_password = request.form["admin_password"]

    admin_id = session.get("user_id")
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Get current admin password hash
    c.execute("SELECT password, username FROM users WHERE id = ?", (admin_id,))
    admin_data = c.fetchone()
    if not admin_data:
        flash("⛔ Admin not found.", "error")
        return redirect(url_for("admin"))

    admin_pass_hash, admin_username = admin_data

    if not check_password_hash(admin_pass_hash, admin_password):
        flash("⛔ Incorrect admin password.", "error")
        return redirect(url_for("admin"))

    # Get target user info (email, old role, username)
    c.execute("SELECT email, role, username FROM users WHERE id = ?", (user_id,))
    target_data = c.fetchone()
    if not target_data:
        flash("⛔ Target user not found.", "error")
        return redirect(url_for("admin"))

    target_email, old_role, target_username = target_data

    # ✅ Send email before updating
    send_role_change_email(
        to_email=target_email,
        username=target_username,
        old_role=old_role,
        new_role=new_role,
        changed_by=admin_username
    )

    # Update role in DB
    c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()

    flash("✅ User role updated & email sent.", "success")
    return redirect(url_for("admin"))


    # Update role
    c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()

    flash("✅ User role updated successfully.", "success")
    return redirect(url_for("admin"))


# delete control for admin (to other users)
@app.route("/delete_user/<int:user_id>", methods=["POST"])
@permission_required("admin")
def delete_user(user_id):
    # Prevent admin from deleting themselves
    if session.get("user_id") == user_id:
        flash("⛔ You can't delete your own account.", "error")
        return redirect(url_for("admin"))

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("✅ User account deleted successfully.", "success")
    return redirect(url_for("admin"))


#file- delete control for admin
@app.route("/delete_file/<filename>", methods=["POST"])
@permission_required("admin")
def delete_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f"🗑️ File '{filename}' deleted successfully.", "success")
    else:
        flash(f"⚠️ File '{filename}' not found.", "error")

    return redirect(url_for("view_uploaded_files"))



#e-mail sender
def send_role_change_email(to_email, username, old_role, new_role, changed_by):
    subject = "🔔 Your Account Role Has Changed"
    body = f"""
    Hello {username},

    Your role has been changed on the DLP platform.

    📌 Old Role: {old_role}
    ✅ New Role: {new_role}
    👤 Changed By: {changed_by}

    If this wasn’t expected, please contact support immediately.

    Regards,
    DLP Security Team
    """

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"[EMAIL] Role change email sent to {to_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")





# --- App Runner ---
if __name__ == "__main__":
    app.run(debug=True)

#tress dont hang around with the grass even though they start with place