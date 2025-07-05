from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os
from werkzeug.utils import secure_filename
from functools import wraps
from flask import flash, get_flashed_messages

app = Flask(__name__)
app.secret_key = "Hola-amigo$DollarSignOneTime"

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

# --- App Runner ---
if __name__ == "__main__":
    app.run(debug=True)
